/*
 * Copyright © 2020 Intel Corporation.
 *     Author: Liu Yi L <yi.l.liu@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Derived from original vfio_pci.c:
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
#include <linux/mdev.h>
#include <linux/vfio_pci_common.h>

#define DRIVER_VERSION  "0.1"
#define DRIVER_AUTHOR   "Liu Yi L <yi.l.liu@intel.com>"
#define DRIVER_DESC     "VFIO Mdev PCI - Sample driver for PCI device as a mdev"

#define VFIO_MDEV_PCI_NAME  "vfio-mdev-pci"

static char ids[1024] __initdata;
module_param_string(ids, ids, sizeof(ids), 0);
MODULE_PARM_DESC(ids, "Initial PCI IDs to add to the vfio-mdev-pci driver, format is \"vendor:device[:subvendor[:subdevice[:class[:class_mask]]]]\" and multiple comma separated entries can be specified");

static bool nointxmask;
module_param_named(nointxmask, nointxmask, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(nointxmask,
		  "Disable support for PCI 2.3 style INTx masking.  If this resolves problems for specific devices, report lspci -vvvxxx to linux-pci@vger.kernel.org so the device can be fixed automatically via the broken_intx_masking flag.");

#ifdef CONFIG_VFIO_PCI_VGA
static bool disable_vga;
module_param(disable_vga, bool, S_IRUGO);
MODULE_PARM_DESC(disable_vga, "Disable VGA resource access through vfio-mdev-pci");
#endif

static bool disable_idle_d3;
module_param(disable_idle_d3, bool, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(disable_idle_d3,
		 "Disable using the PCI D3 low power state for idle, unused devices");

static struct pci_driver vfio_mdev_pci_driver;

static ssize_t
name_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "%s-type1\n", dev_name(dev));
}

MDEV_TYPE_ATTR_RO(name);

static ssize_t
available_instances_show(struct kobject *kobj, struct device *dev, char *buf)
{
	return sprintf(buf, "%d\n", 1);
}

MDEV_TYPE_ATTR_RO(available_instances);

static ssize_t device_api_show(struct kobject *kobj, struct device *dev,
		char *buf)
{
	return sprintf(buf, "%s\n", VFIO_DEVICE_API_PCI_STRING);
}

MDEV_TYPE_ATTR_RO(device_api);

static struct attribute *vfio_mdev_pci_types_attrs[] = {
	&mdev_type_attr_name.attr,
	&mdev_type_attr_device_api.attr,
	&mdev_type_attr_available_instances.attr,
	NULL,
};

static struct attribute_group vfio_mdev_pci_type_group1 = {
	.name  = "type1",
	.attrs = vfio_mdev_pci_types_attrs,
};

struct attribute_group *vfio_mdev_pci_type_groups[] = {
	&vfio_mdev_pci_type_group1,
	NULL,
};

struct vfio_mdev_pci {
	struct vfio_pci_device *vdev;
	struct mdev_device *mdev;
	unsigned long handle;
};

static int vfio_mdev_pci_create(struct kobject *kobj, struct mdev_device *mdev)
{
	struct device *pdev;
	struct vfio_pci_device *vdev;
	struct vfio_mdev_pci *pmdev;
	int ret;

	pdev = mdev_parent_dev(mdev);
	vdev = dev_get_drvdata(pdev);
	pmdev = kzalloc(sizeof(struct vfio_mdev_pci), GFP_KERNEL);
	if (pmdev == NULL) {
		ret = -EBUSY;
		goto out;
	}

	pmdev->mdev = mdev;
	pmdev->vdev = vdev;
	mdev_set_drvdata(mdev, pmdev);
	ret = mdev_set_iommu_device(mdev_dev(mdev), pdev);
	if (ret) {
		pr_info("%s, failed to config iommu isolation for mdev: %s on pf: %s\n",
			__func__, dev_name(mdev_dev(mdev)), dev_name(pdev));
		goto out;
	}

	pr_info("%s, creation succeeded for mdev: %s\n", __func__,
		     dev_name(mdev_dev(mdev)));
out:
	return ret;
}

static int vfio_mdev_pci_remove(struct mdev_device *mdev)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);

	kfree(pmdev);
	pr_info("%s, succeeded for mdev: %s\n", __func__,
		     dev_name(mdev_dev(mdev)));

	return 0;
}

static int vfio_mdev_pci_open(struct mdev_device *mdev)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);
	struct vfio_pci_device *vdev = pmdev->vdev;
	int ret = 0;

	if (!try_module_get(THIS_MODULE))
		return -ENODEV;

	ret = vfio_pci_open_common(vdev, nointxmask, disable_idle_d3, false);

	if (!ret)
		pr_info("Succeeded to open mdev: %s on pf: %s\n",
		dev_name(mdev_dev(mdev)), dev_name(&pmdev->vdev->pdev->dev));
	else {
		pr_info("Failed to open mdev: %s on pf: %s\n",
		dev_name(mdev_dev(mdev)), dev_name(&pmdev->vdev->pdev->dev));
		module_put(THIS_MODULE);
	}
	return ret;
}

static void vfio_mdev_pci_release(struct mdev_device *mdev)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);
	struct vfio_pci_device *vdev = pmdev->vdev;

	pr_info("Release mdev: %s on pf: %s\n",
		dev_name(mdev_dev(mdev)), dev_name(&pmdev->vdev->pdev->dev));

	vfio_pci_release_common(vdev, false);

	module_put(THIS_MODULE);
}

static long vfio_mdev_pci_ioctl(struct mdev_device *mdev, unsigned int cmd,
			     unsigned long arg)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);

	return vfio_pci_ioctl(pmdev->vdev, cmd, arg);
}

static int vfio_mdev_pci_mmap(struct mdev_device *mdev,
				struct vm_area_struct *vma)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);

	return vfio_pci_mmap(pmdev->vdev, vma);
}

static ssize_t vfio_mdev_pci_read(struct mdev_device *mdev, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);

	return vfio_pci_read(pmdev->vdev, buf, count, ppos);
}

static ssize_t vfio_mdev_pci_write(struct mdev_device *mdev,
				const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct vfio_mdev_pci *pmdev = mdev_get_drvdata(mdev);

	return vfio_pci_write(pmdev->vdev, (char __user *)buf, count, ppos);
}

static const struct mdev_parent_ops vfio_mdev_pci_ops = {
	.supported_type_groups	= vfio_mdev_pci_type_groups,
	.create			= vfio_mdev_pci_create,
	.remove			= vfio_mdev_pci_remove,

	.open			= vfio_mdev_pci_open,
	.release		= vfio_mdev_pci_release,

	.read			= vfio_mdev_pci_read,
	.write			= vfio_mdev_pci_write,
	.mmap			= vfio_mdev_pci_mmap,
	.ioctl			= vfio_mdev_pci_ioctl,
};

static int vfio_mdev_pci_driver_probe(struct pci_dev *pdev,
				       const struct pci_device_id *id)
{
	struct vfio_pci_device *vdev;
	int ret;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vfio_pci_probe_common(pdev, id, vdev);

#ifdef CONFIG_VFIO_PCI_VGA
	vdev->disable_vga = disable_vga;
#endif
	vfio_pci_refresh_config(vdev, nointxmask, disable_idle_d3);

	pci_set_drvdata(pdev, vdev);

	ret = vfio_pci_reflck_attach(vdev);
	if (ret) {
		pci_set_drvdata(pdev, NULL);
		kfree(vdev);
		return ret;
	}

	vfio_pci_probe_common_sec(pdev, vdev);

	ret = mdev_register_device(&pdev->dev, &vfio_mdev_pci_ops);
	if (ret)
		pr_err("Cannot register mdev for device %s\n",
			dev_name(&pdev->dev));
	else
		pr_info("Wrap device %s as a mdev\n", dev_name(&pdev->dev));

	return ret;
}

static void vfio_mdev_pci_driver_remove(struct pci_dev *pdev)
{
	struct vfio_pci_device *vdev;

	vdev = pci_get_drvdata(pdev);
	if (!vdev)
		return;

	vfio_pci_remove_common(pdev, vdev);

	kfree(vdev);
}

static struct pci_driver vfio_mdev_pci_driver = {
	.name		= VFIO_MDEV_PCI_NAME,
	.id_table	= NULL, /* only dynamic ids */
	.probe		= vfio_mdev_pci_driver_probe,
	.remove		= vfio_mdev_pci_driver_remove,
	.err_handler	= &vfio_pci_err_handlers,
};

static void __exit vfio_mdev_pci_cleanup(void)
{
	pci_unregister_driver(&vfio_mdev_pci_driver);
}

static int __init vfio_mdev_pci_init(void)
{
	int ret;

	/* Register and scan for devices */
	ret = pci_register_driver(&vfio_mdev_pci_driver);
	if (ret)
		return ret;

	vfio_pci_ids(ids, &vfio_mdev_pci_driver);

	return 0;
}

module_init(vfio_mdev_pci_init);
module_exit(vfio_mdev_pci_cleanup);

MODULE_VERSION(DRIVER_VERSION);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR(DRIVER_AUTHOR);
MODULE_DESCRIPTION(DRIVER_DESC);
