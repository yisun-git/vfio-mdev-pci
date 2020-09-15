/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Red Hat, Inc.  All rights reserved.
 *     Author: Alex Williamson <alex.williamson@redhat.com>
 *
 * Derived from original vfio:
 * Copyright 2010 Cisco Systems, Inc.  All rights reserved.
 * Author: Tom Lyon, pugs@cisco.com
 */

#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/irqbypass.h>
#include <linux/types.h>
#include <linux/uuid.h>
#include <linux/notifier.h>
#include <linux/vfio_pci_common.h>

#ifndef VFIO_PCI_PRIVATE_H
#define VFIO_PCI_PRIVATE_H

#define VFIO_PCI_OFFSET_SHIFT   40

#define VFIO_PCI_OFFSET_TO_INDEX(off)	(off >> VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_INDEX_TO_OFFSET(index)	((u64)(index) << VFIO_PCI_OFFSET_SHIFT)
#define VFIO_PCI_OFFSET_MASK	(((u64)(1) << VFIO_PCI_OFFSET_SHIFT) - 1)

/* Special capability IDs predefined access */
#define PCI_CAP_ID_INVALID		0xFF	/* default raw access */
#define PCI_CAP_ID_INVALID_VIRT		0xFE	/* default virt access */

/* Cap maximum number of ioeventfds per device (arbitrary) */
#define VFIO_PCI_IOEVENTFD_MAX		1000

struct vfio_pci_ioeventfd {
	struct list_head	next;
	struct vfio_pci_device	*vdev;
	struct virqfd		*virqfd;
	void __iomem		*addr;
	uint64_t		data;
	loff_t			pos;
	int			bar;
	int			count;
	bool			test_mem;
};

struct vfio_pci_irq_ctx {
	struct eventfd_ctx	*trigger;
	struct virqfd		*unmask;
	struct virqfd		*mask;
	char			*name;
	bool			masked;
	struct irq_bypass_producer	producer;
};

struct vfio_pci_dummy_resource {
	struct resource		resource;
	int			index;
	struct list_head	res_next;
};

struct vfio_pci_reflck {
	struct kref		kref;
	struct mutex		lock;
};

struct vfio_pci_mmap_vma {
	struct vm_area_struct	*vma;
	struct list_head	vma_next;
};

#define is_intx(vdev) (vdev->irq_type == VFIO_PCI_INTX_IRQ_INDEX)
#define is_msi(vdev) (vdev->irq_type == VFIO_PCI_MSI_IRQ_INDEX)
#define is_msix(vdev) (vdev->irq_type == VFIO_PCI_MSIX_IRQ_INDEX)
#define is_irq_none(vdev) (!(is_intx(vdev) || is_msi(vdev) || is_msix(vdev)))
#define irq_is(vdev, type) (vdev->irq_type == type)

static inline bool vfio_vga_disabled(struct vfio_pci_device *vdev)
{
#ifdef CONFIG_VFIO_PCI_VGA
	return vdev->disable_vga;
#else
	return true;
#endif
}

extern void vfio_pci_intx_mask(struct vfio_pci_device *vdev);
extern void vfio_pci_intx_unmask(struct vfio_pci_device *vdev);

extern int vfio_pci_set_irqs_ioctl(struct vfio_pci_device *vdev,
				   uint32_t flags, unsigned index,
				   unsigned start, unsigned count, void *data);

extern ssize_t vfio_pci_config_rw(struct vfio_pci_device *vdev,
				  char __user *buf, size_t count,
				  loff_t *ppos, bool iswrite);

extern ssize_t vfio_pci_bar_rw(struct vfio_pci_device *vdev, char __user *buf,
			       size_t count, loff_t *ppos, bool iswrite);

extern ssize_t vfio_pci_vga_rw(struct vfio_pci_device *vdev, char __user *buf,
			       size_t count, loff_t *ppos, bool iswrite);

extern long vfio_pci_ioeventfd(struct vfio_pci_device *vdev, loff_t offset,
			       uint64_t data, int count, int fd);

extern int vfio_pci_init_perm_bits(void);
extern void vfio_pci_uninit_perm_bits(void);

extern int vfio_config_init(struct vfio_pci_device *vdev);
extern void vfio_config_free(struct vfio_pci_device *vdev);

extern bool __vfio_pci_memory_enabled(struct vfio_pci_device *vdev);

#ifdef CONFIG_VFIO_PCI_IGD
extern int vfio_pci_igd_init(struct vfio_pci_device *vdev);
#else
static inline int vfio_pci_igd_init(struct vfio_pci_device *vdev)
{
	return -ENODEV;
}
#endif
#ifdef CONFIG_VFIO_PCI_NVLINK2
extern int vfio_pci_nvdia_v100_nvlink2_init(struct vfio_pci_device *vdev);
extern int vfio_pci_ibm_npu2_init(struct vfio_pci_device *vdev);
#else
static inline int vfio_pci_nvdia_v100_nvlink2_init(struct vfio_pci_device *vdev)
{
	return -ENODEV;
}

static inline int vfio_pci_ibm_npu2_init(struct vfio_pci_device *vdev)
{
	return -ENODEV;
}
#endif
#endif /* VFIO_PCI_PRIVATE_H */
