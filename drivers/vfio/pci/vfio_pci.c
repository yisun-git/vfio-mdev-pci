// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/device.h>
#include <linux/eventfd.h>
#include <linux/file.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/notifier.h>
#include <linux/pci.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/vfio.h>
#include <linux/vgaarb.h>
#include <linux/nospec.h>
#include <linux/sched/mm.h>

#include "vfio_pci_private.h"

#define DRIVER_VERSION  "0.2"
#define DRIVER_AUTHOR   "Alex Williamson <alex.williamson@redhat.com>"
#define DRIVER_DESC     "VFIO PCI - User Level meta-driver"

static char ids[1024] __initdata;
module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the vfio driver, format is \"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\" and multiple comma separated entries can be specified");

static bool nointxmask;
module_param_named(nointxmask, nointxmask, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(nointxmask,
		  "Disable support for PCI 2.3 style INTx masking.  If this resolves problems for specific devices, report lspci -vvvxxx to linux-pci@vger.kernel.org so the device can be fixed automatically via the broken_intx_masking flag.");

#ifdef CONFIG_VFIO_PCI_VGA
static bool disable_vga;
module_param(disable_vga, bool, S_IRUGO);
MODULE_PARM_DESC(disable_vga, "Disable VGA resource access through vfio-pci");
#endif

static bool disable_idle_d3;
module_param(disable_idle_d3, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(disable_idle_d3,
		 "Disable using the PCI D3 low power state for idle, unused devices");

static bool enable_sriov;
#ifdef CONFIG_PCI_IOV
module_param(enable_sriov, bool, 0644);
MODULE_PARM_DESC(enable_sriov, "Enable support for SR-IOV configuration.  Enabling SR-IOV on a PF typically requires support of the userspace PF driver, enabling VFs without such support may result in non-functional VFs or PF.");
#endif

static bool disable_denylist;
module_param(disable_denylist, bool, 0444);
MODULE_PARM_DESC(disable_denylist, "Disable use of device denylist. Disabling the denylist allows binding to devices with known errata that may lead to exploitable stability or security issues when accessed by untrusted users.");

static bool vfio_pci_dev_in_denylist(struct pci_dev *pdev)
{
	switch (pdev->vendor) {
	case PCI_VENDOR_ID_INTEL:
		switch (pdev->device) {
		case PCI_DEVICE_ID_INTEL_QAT_C3XXX:
		case PCI_DEVICE_ID_INTEL_QAT_C3XXX_VF:
		case PCI_DEVICE_ID_INTEL_QAT_C62X:
		case PCI_DEVICE_ID_INTEL_QAT_C62X_VF:
		case PCI_DEVICE_ID_INTEL_QAT_DH895XCC:
		case PCI_DEVICE_ID_INTEL_QAT_DH895XCC_VF:
			return true;
		default:
			return false;
		}
	}

	return false;
}

static bool vfio_pci_is_denylisted(struct pci_dev *pdev)
{
	if (!vfio_pci_dev_in_denylist(pdev))
		return false;

	if (disable_denylist) {
		pci_warn(pdev,
			 "device denylist disabled - allowing device %04x:%04x.\n",
			 pdev->vendor, pdev->device);
		return false;
	}

	pci_warn(pdev, "%04x:%04x exists in vfio-pci device denylist, driver probing disallowed.\n",
		 pdev->vendor, pdev->device);

	return true;
}

static struct pci_driver vfio_pci_driver;

static struct vfio_pci_device *get_pf_vdev(struct vfio_pci_device *vdev,
					   struct vfio_device **pf_dev)
{
	struct pci_dev *physfn = pci_physfn(vdev->pdev);

	if (!vdev->pdev->is_virtfn)
		return NULL;

	*pf_dev = vfio_device_get_from_dev(&physfn->dev);
	if (!*pf_dev)
		return NULL;

	if (pci_dev_driver(physfn) != &vfio_pci_driver) {
		vfio_device_put(*pf_dev);
		return NULL;
	}

	return vfio_device_data(*pf_dev);
}

static void vfio_pci_vf_token_user_add(struct vfio_pci_device *vdev, int val)
{
	struct vfio_device *pf_dev;
	struct vfio_pci_device *pf_vdev = get_pf_vdev(vdev, &pf_dev);

	if (!pf_vdev)
		return;

	mutex_lock(&pf_vdev->vf_token->lock);
	pf_vdev->vf_token->users += val;
	WARN_ON(pf_vdev->vf_token->users < 0);
	mutex_unlock(&pf_vdev->vf_token->lock);

	vfio_device_put(pf_dev);
}

static void vfio_pci_release(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;

	mutex_lock(&vdev->reflck->lock);

	if (!(--vdev->refcnt)) {
		vfio_pci_vf_token_user_add(vdev, -1);
		vfio_spapr_pci_eeh_release(vdev->pdev);
		vfio_pci_disable(vdev);

		mutex_lock(&vdev->igate);
		if (vdev->err_trigger) {
			eventfd_ctx_put(vdev->err_trigger);
			vdev->err_trigger = NULL;
		}
		if (vdev->req_trigger) {
			eventfd_ctx_put(vdev->req_trigger);
			vdev->req_trigger = NULL;
		}
		mutex_unlock(&vdev->igate);
	}

	mutex_unlock(&vdev->reflck->lock);

	module_put(THIS_MODULE);
}

static int vfio_pci_open(void *device_data)
{
	struct vfio_pci_device *vdev = device_data;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	vfio_pci_refresh_config(vdev, nointxmask, disable_idle_d3);

	mutex_lock(&vdev->reflck->lock);

	if (!vdev->refcnt) {
		ret = vfio_pci_enable(vdev);
		if (ret)
			goto error;

		vfio_spapr_pci_eeh_open(vdev->pdev);
		vfio_pci_vf_token_user_add(vdev, 1);
	}
	vdev->refcnt++;
error:
	mutex_unlock(&vdev->reflck->lock);
	if (ret)
		module_put(THIS_MODULE);
	return ret;
}

static int vfio_pci_validate_vf_token(struct vfio_pci_device *vdev,
				      bool vf_token, uuid_t *uuid)
{
	/*
	 * There's always some degree of trust or collaboration between SR-IOV
	 * PF and VFs, even if just that the PF hosts the SR-IOV capability and
	 * can disrupt VFs with a reset, but often the PF has more explicit
	 * access to deny service to the VF or access data passed through the
	 * VF.  We therefore require an opt-in via a shared VF token (UUID) to
	 * represent this trust.  This both prevents that a VF driver might
	 * assume the PF driver is a trusted, in-kernel driver, and also that
	 * a PF driver might be replaced with a rogue driver, unknown to in-use
	 * VF drivers.
	 *
	 * Therefore when presented with a VF, if the PF is a vfio device and
	 * it is bound to the vfio-pci driver, the user needs to provide a VF
	 * token to access the device, in the form of appending a vf_token to
	 * the device name, for example:
	 *
	 * "0000:04:10.0 vf_token=bd8d9d2b-5a5f-4f5a-a211-f591514ba1f3"
	 *
	 * When presented with a PF which has VFs in use, the user must also
	 * provide the current VF token to prove collaboration with existing
	 * VF users.  If VFs are not in use, the VF token provided for the PF
	 * device will act to set the VF token.
	 *
	 * If the VF token is provided but unused, an error is generated.
	 */
	if (!vdev->pdev->is_virtfn && !vdev->vf_token && !vf_token)
		return 0; /* No VF token provided or required */

	if (vdev->pdev->is_virtfn) {
		struct vfio_device *pf_dev;
		struct vfio_pci_device *pf_vdev = get_pf_vdev(vdev, &pf_dev);
		bool match;

		if (!pf_vdev) {
			if (!vf_token)
				return 0; /* PF is not vfio-pci, no VF token */

			pci_info_ratelimited(vdev->pdev,
				"VF token incorrectly provided, PF not bound to vfio-pci\n");
			return -EINVAL;
		}

		if (!vf_token) {
			vfio_device_put(pf_dev);
			pci_info_ratelimited(vdev->pdev,
				"VF token required to access device\n");
			return -EACCES;
		}

		mutex_lock(&pf_vdev->vf_token->lock);
		match = uuid_equal(uuid, &pf_vdev->vf_token->uuid);
		mutex_unlock(&pf_vdev->vf_token->lock);

		vfio_device_put(pf_dev);

		if (!match) {
			pci_info_ratelimited(vdev->pdev,
				"Incorrect VF token provided for device\n");
			return -EACCES;
		}
	} else if (vdev->vf_token) {
		mutex_lock(&vdev->vf_token->lock);
		if (vdev->vf_token->users) {
			if (!vf_token) {
				mutex_unlock(&vdev->vf_token->lock);
				pci_info_ratelimited(vdev->pdev,
					"VF token required to access device\n");
				return -EACCES;
			}

			if (!uuid_equal(uuid, &vdev->vf_token->uuid)) {
				mutex_unlock(&vdev->vf_token->lock);
				pci_info_ratelimited(vdev->pdev,
					"Incorrect VF token provided for device\n");
				return -EACCES;
			}
		} else if (vf_token) {
			uuid_copy(&vdev->vf_token->uuid, uuid);
		}

		mutex_unlock(&vdev->vf_token->lock);
	} else if (vf_token) {
		pci_info_ratelimited(vdev->pdev,
			"VF token incorrectly provided, not a PF or VF\n");
		return -EINVAL;
	}

	return 0;
}

#define VF_TOKEN_ARG "vf_token="

static int vfio_pci_match(void *device_data, char *buf)
{
	struct vfio_pci_device *vdev = device_data;
	bool vf_token = false;
	uuid_t uuid;
	int ret;

	if (strncmp(pci_name(vdev->pdev), buf, strlen(pci_name(vdev->pdev))))
		return 0; /* No match */

	if (strlen(buf) > strlen(pci_name(vdev->pdev))) {
		buf += strlen(pci_name(vdev->pdev));

		if (*buf != ' ')
			return 0; /* No match: non-whitespace after name */

		while (*buf) {
			if (*buf == ' ') {
				buf++;
				continue;
			}

			if (!vf_token && !strncmp(buf, VF_TOKEN_ARG,
						  strlen(VF_TOKEN_ARG))) {
				buf += strlen(VF_TOKEN_ARG);

				if (strlen(buf) < UUID_STRING_LEN)
					return -EINVAL;

				ret = uuid_parse(buf, &uuid);
				if (ret)
					return ret;

				vf_token = true;
				buf += UUID_STRING_LEN;
			} else {
				/* Unknown/duplicate option */
				return -EINVAL;
			}
		}
	}

	ret = vfio_pci_validate_vf_token(vdev, vf_token, &uuid);
	if (ret)
		return ret;

	return 1; /* Match */
}

static const struct vfio_device_ops vfio_pci_ops = {
	.name		= "vfio-pci",
	.open		= vfio_pci_open,
	.release	= vfio_pci_release,
	.ioctl		= vfio_pci_ioctl,
	.read		= vfio_pci_read,
	.write		= vfio_pci_write,
	.mmap		= vfio_pci_mmap,
	.request	= vfio_pci_request,
	.match		= vfio_pci_match,
};

static struct pci_driver vfio_pci_driver;

static int vfio_pci_bus_notifier(struct notifier_block *nb,
				 unsigned long action, void *data)
{
	struct vfio_pci_device *vdev = container_of(nb,
						    struct vfio_pci_device, nb);
	struct device *dev = data;
	struct pci_dev *pdev = to_pci_dev(dev);
	struct pci_dev *physfn = pci_physfn(pdev);

	if (action == BUS_NOTIFY_ADD_DEVICE &&
	    pdev->is_virtfn && physfn == vdev->pdev) {
		pci_info(vdev->pdev, "Captured SR-IOV VF %s driver_override\n",
			 pci_name(pdev));
		pdev->driver_override = kasprintf(GFP_KERNEL, "%s",
						  vfio_pci_ops.name);
	} else if (action == BUS_NOTIFY_BOUND_DRIVER &&
		   pdev->is_virtfn && physfn == vdev->pdev) {
		struct pci_driver *drv = pci_dev_driver(pdev);

		if (drv && drv != &vfio_pci_driver)
			pci_warn(vdev->pdev,
				 "VF %s bound to driver %s while PF bound to vfio-pci\n",
				 pci_name(pdev), drv->name);
	}

	return 0;
}

static int vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct vfio_pci_device *vdev;
	struct iommu_group *group;
	int ret;

	if (vfio_pci_is_denylisted(pdev))
		return -EINVAL;

	if (pdev->hdr_type != PCI_HEADER_TYPE_NORMAL)
		return -EINVAL;

	/*
	 * Prevent binding to PFs with VFs enabled, the VFs might be in use
	 * by the host or other users.  We cannot capture the VFs if they
	 * already exist, nor can we track VF users.  Disabling SR-IOV here
	 * would initiate removing the VFs, which would unbind the driver,
	 * which is prone to blocking if that VF is also in use by vfio-pci.
	 * Just reject these PFs and let the user sort it out.
	 */
	if (pci_num_vf(pdev)) {
		pci_warn(pdev, "Cannot bind to PF with SR-IOV enabled\n");
		return -EBUSY;
	}

	group = vfio_iommu_group_get(&pdev->dev);
	if (!group)
		return -EINVAL;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev) {
		ret = -ENOMEM;
		goto out_group_put;
	}

	vdev->pdev = pdev;
	vdev->irq_type = VFIO_PCI_NUM_IRQS;
	mutex_init(&vdev->igate);
	spin_lock_init(&vdev->irqlock);
	mutex_init(&vdev->ioeventfds_lock);
	INIT_LIST_HEAD(&vdev->ioeventfds_list);
	mutex_init(&vdev->vma_lock);
	INIT_LIST_HEAD(&vdev->vma_list);
	init_rwsem(&vdev->memory_lock);
#ifdef CONFIG_VFIO_PCI_VGA
	vdev->disable_vga = disable_vga;
#endif
	vfio_pci_refresh_config(vdev, nointxmask, disable_idle_d3);


	ret = vfio_add_group_dev(&pdev->dev, &vfio_pci_ops, vdev);
	if (ret)
		goto out_free;

	ret = vfio_pci_reflck_attach(vdev);
	if (ret)
		goto out_del_group_dev;

	if (pdev->is_physfn) {
		vdev->vf_token = kzalloc(sizeof(*vdev->vf_token), GFP_KERNEL);
		if (!vdev->vf_token) {
			ret = -ENOMEM;
			goto out_reflck;
		}

		mutex_init(&vdev->vf_token->lock);
		uuid_gen(&vdev->vf_token->uuid);

		vdev->nb.notifier_call = vfio_pci_bus_notifier;
		ret = bus_register_notifier(&pci_bus_type, &vdev->nb);
		if (ret)
			goto out_vf_token;
	}

	if (vfio_pci_is_vga(pdev)) {
		vga_client_register(pdev, vdev, NULL, vfio_pci_set_vga_decode);
		vga_set_legacy_decoding(pdev,
					vfio_pci_set_vga_decode(vdev, false));
	}

	vfio_pci_probe_power_state(vdev);

	if (!vdev->disable_idle_d3) {
		/*
		 * pci-core sets the device power state to an unknown value at
		 * bootup and after being removed from a driver.  The only
		 * transition it allows from this unknown state is to D0, which
		 * typically happens when a driver calls pci_enable_device().
		 * We're not ready to enable the device yet, but we do want to
		 * be able to get to D3.  Therefore first do a D0 transition
		 * before going to D3.
		 */
		vfio_pci_set_power_state(vdev, PCI_D0);
		vfio_pci_set_power_state(vdev, PCI_D3hot);
	}

	return ret;

out_vf_token:
	kfree(vdev->vf_token);
out_reflck:
	vfio_pci_reflck_put(vdev->reflck);
out_del_group_dev:
	vfio_del_group_dev(&pdev->dev);
out_free:
	kfree(vdev);
out_group_put:
	vfio_iommu_group_put(group, &pdev->dev);
	return ret;
}

static void vfio_pci_remove(struct pci_dev *pdev)
{
	struct vfio_pci_device *vdev;

	pci_disable_sriov(pdev);

	vdev = vfio_del_group_dev(&pdev->dev);
	if (!vdev)
		return;

	if (vdev->vf_token) {
		WARN_ON(vdev->vf_token->users);
		mutex_destroy(&vdev->vf_token->lock);
		kfree(vdev->vf_token);
	}

	if (vdev->nb.notifier_call)
		bus_unregister_notifier(&pci_bus_type, &vdev->nb);

	vfio_pci_reflck_put(vdev->reflck);

	vfio_iommu_group_put(pdev->dev.iommu_group, &pdev->dev);
	kfree(vdev->region);
	mutex_destroy(&vdev->ioeventfds_lock);

	if (!vdev->disable_idle_d3)
		vfio_pci_set_power_state(vdev, PCI_D0);

	kfree(vdev->pm_save);
	kfree(vdev);

	if (vfio_pci_is_vga(pdev)) {
		vga_client_register(pdev, NULL, NULL, NULL);
		vga_set_legacy_decoding(pdev,
				VGA_RSRC_NORMAL_IO | VGA_RSRC_NORMAL_MEM |
				VGA_RSRC_LEGACY_IO | VGA_RSRC_LEGACY_MEM);
	}
}

static int vfio_pci_sriov_configure(struct pci_dev *pdev, int nr_virtfn)
{
	struct vfio_pci_device *vdev;
	struct vfio_device *device;
	int ret = 0;

	might_sleep();

	if (!enable_sriov)
		return -ENOENT;

	device = vfio_device_get_from_dev(&pdev->dev);
	if (!device)
		return -ENODEV;

	vdev = vfio_device_data(device);
	if (!vdev) {
		vfio_device_put(device);
		return -ENODEV;
	}

	if (nr_virtfn == 0)
		pci_disable_sriov(pdev);
	else
		ret = pci_enable_sriov(pdev, nr_virtfn);

	vfio_device_put(device);

	return ret < 0 ? ret : nr_virtfn;
}

static struct pci_driver vfio_pci_driver = {
	.name			= "vfio-pci",
	.id_table		= NULL, /* only dynamic ids */
	.probe			= vfio_pci_probe,
	.remove			= vfio_pci_remove,
	.sriov_configure	= vfio_pci_sriov_configure,
	.err_handler		= &vfio_err_handlers,
};

static void __exit vfio_pci_cleanup(void)
{
	pci_unregister_driver(&vfio_pci_driver);
	vfio_pci_uninit_perm_bits();
}

static int __init vfio_pci_init(void)
{
	int ret;

	/* Allocate shared config space permision data used by all devices */
	ret = vfio_pci_init_perm_bits();
	if (ret)
		return ret;

	/* Register and scan for devices */
	ret = pci_register_driver(&vfio_pci_driver);
	if (ret)
		goto out_driver;

	vfio_pci_ids(ids, &vfio_pci_driver);

	if (disable_denylist)
		pr_warn("device denylist disabled.\n");

	return 0;

out_driver:
	vfio_pci_uninit_perm_bits();
	return ret;
}

module_init(vfio_pci_init);
module_exit(vfio_pci_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
