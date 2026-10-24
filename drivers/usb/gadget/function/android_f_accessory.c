// SPDX-License-Identifier: GPL-2.0
/*
 * Gadget Function Driver for Android USB accessories
 *
 * Copyright 2011-2024 Google LLC
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/kref.h>
#include <linux/kernel.h>

#include <linux/types.h>
#include <linux/file.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#include <linux/hid.h>
#include <linux/hiddev.h>
#include <linux/usb.h>
#include <linux/usb/ch9.h>
#include <linux/usb/android_accessory.h>
#include <uapi/linux/usb/android_accessory.h>

#include <linux/configfs.h>
#include <linux/usb/composite.h>

#define MAX_INST_NAME_LEN 40
#define BULK_BUFFER_SIZE 16384

#define PROTOCOL_VERSION 2

/* String IDs */
#define INTERFACE_STRING_INDEX 0

/* number of tx and rx requests to allocate */
#define TX_REQ_MAX 4
#define RX_REQ_MAX 2

/* Safe upper bound for a HID report descriptor*/
#define MAX_HID_DESC_SIZE 4096

/* Maximum number of concurrent AOA‑HID devices*/
#define MAX_HID_DEVICES 32

/* Include devices awaiting control completion or deferred destruction. */
#define MAX_HID_ALLOCATIONS (2 * MAX_HID_DEVICES)

struct acc_hid_dev {
	struct list_head list;
	struct kref kref;
	struct work_struct release_work;
	bool dead;
	bool initializing;
	struct hid_device *hid;
	struct acc_dev *dev;
	/* accessory defined ID */
	int id;
	/* HID report descriptor */
	u8 *report_desc;
	/* length of HID report descriptor */
	int report_desc_len;
	/* number of bytes of report_desc we have received so far */
	int report_desc_offset;
};

struct acc_dev {
	struct usb_function function;
	struct usb_composite_dev *cdev;
	spinlock_t lock;
	struct kref kref;
	struct work_struct release_work;
	struct device *device;
	bool closing;
	unsigned int hid_count;

	struct usb_ep *ep_in;
	struct usb_ep *ep_out;

	/*
	 * online indicates state of function_set_alt & function_unbind
	 * set to true when we connect
	 */
	bool online;

	/*
	 * disconnected indicates state of open & release
	 * Set to true when we disconnect.
	 */
	bool disconnected;

	/* strings sent by the host */
	char manufacturer[ACC_STRING_SIZE];
	char model[ACC_STRING_SIZE];
	char description[ACC_STRING_SIZE];
	char version[ACC_STRING_SIZE];
	char uri[ACC_STRING_SIZE];
	char serial[ACC_STRING_SIZE];

	/* set to 1 if we have a pending start request */
	int start_requested;

	int audio_mode;

	struct list_head tx_idle;

	wait_queue_head_t read_wq;
	wait_queue_head_t write_wq;
	struct usb_request *rx_req[RX_REQ_MAX];
	int rx_done;

	/* delayed work for handling ACCESSORY_START */
	struct delayed_work start_work;

	/* work for handling ACCESSORY GET PROTOCOL */
	struct work_struct getprotocol_work;

	/* work for handling ACCESSORY SEND STRING */
	struct work_struct sendstring_work;

	/* worker for registering and unregistering hid devices */
	struct work_struct hid_work;

	/* list of active HID devices */
	struct list_head hid_list;

	/* list of new HID devices to register */
	struct list_head new_hid_list;

	/* list of dead HID devices to unregister */
	struct list_head dead_hid_list;
};

struct acc_control_request {
	struct acc_dev *dev;
	struct acc_hid_dev *hid;
	void (*complete)(struct usb_ep *, struct usb_request *);
	u16 index;
	u16 length;
};

static struct usb_interface_descriptor acc_interface_desc = {
	.bLength                = USB_DT_INTERFACE_SIZE,
	.bDescriptorType        = USB_DT_INTERFACE,
	.bInterfaceNumber       = 0,
	.bNumEndpoints          = 2,
	.bInterfaceClass        = USB_CLASS_VENDOR_SPEC,
	.bInterfaceSubClass     = USB_SUBCLASS_VENDOR_SPEC,
	.bInterfaceProtocol     = 0,
};

static struct usb_endpoint_descriptor acc_superspeedplus_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_endpoint_descriptor acc_superspeedplus_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor acc_superspeedplus_comp_desc = {
	.bLength                = sizeof(acc_superspeedplus_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	.bMaxBurst              = 6,
	/* .bmAttributes =      0, */
};

static struct usb_endpoint_descriptor acc_superspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_endpoint_descriptor acc_superspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(1024),
};

static struct usb_ss_ep_comp_descriptor acc_superspeed_comp_desc = {
	.bLength                = sizeof(acc_superspeed_comp_desc),
	.bDescriptorType        = USB_DT_SS_ENDPOINT_COMP,

	/* the following 2 values can be tweaked if necessary */
	.bMaxBurst              = 6,
	/* .bmAttributes =      0, */
};

static struct usb_endpoint_descriptor acc_highspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(512),
};

static struct usb_endpoint_descriptor acc_highspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
	.wMaxPacketSize         = cpu_to_le16(512),
};

static struct usb_endpoint_descriptor acc_fullspeed_in_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_IN,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_endpoint_descriptor acc_fullspeed_out_desc = {
	.bLength                = USB_DT_ENDPOINT_SIZE,
	.bDescriptorType        = USB_DT_ENDPOINT,
	.bEndpointAddress       = USB_DIR_OUT,
	.bmAttributes           = USB_ENDPOINT_XFER_BULK,
};

static struct usb_descriptor_header *fs_acc_descs[] = {
	(struct usb_descriptor_header *) &acc_interface_desc,
	(struct usb_descriptor_header *) &acc_fullspeed_in_desc,
	(struct usb_descriptor_header *) &acc_fullspeed_out_desc,
	NULL,
};

static struct usb_descriptor_header *hs_acc_descs[] = {
	(struct usb_descriptor_header *) &acc_interface_desc,
	(struct usb_descriptor_header *) &acc_highspeed_in_desc,
	(struct usb_descriptor_header *) &acc_highspeed_out_desc,
	NULL,
};

static struct usb_descriptor_header *ss_acc_descs[] = {
	(struct usb_descriptor_header *) &acc_interface_desc,
	(struct usb_descriptor_header *) &acc_superspeed_in_desc,
	(struct usb_descriptor_header *) &acc_superspeed_comp_desc,
	(struct usb_descriptor_header *) &acc_superspeed_out_desc,
	(struct usb_descriptor_header *) &acc_superspeed_comp_desc,
	NULL,
};

static struct usb_descriptor_header *ssp_acc_descs[] = {
	(struct usb_descriptor_header *) &acc_interface_desc,
	(struct usb_descriptor_header *) &acc_superspeedplus_in_desc,
	(struct usb_descriptor_header *) &acc_superspeedplus_comp_desc,
	(struct usb_descriptor_header *) &acc_superspeedplus_out_desc,
	(struct usb_descriptor_header *) &acc_superspeedplus_comp_desc,
	NULL,
};

static struct usb_string acc_string_defs[] = {
	[INTERFACE_STRING_INDEX].s = "Android Accessory Interface",
	{  }, /* end of list */
};

static struct usb_gadget_strings acc_string_table = {
	.language		= 0x0409, /* en-US */
	.strings		= acc_string_defs,
};

static struct usb_gadget_strings *acc_strings[] = {
	&acc_string_table,
	NULL,
};

static DEFINE_SPINLOCK(acc_dev_instance_lock);
static struct acc_dev *acc_dev_instance;
static bool acc_dev_instance_creating;

struct acc_instance {
	struct usb_function_instance func_inst;
	const char *name;
};

static struct acc_dev *get_acc_dev(void)
{
	struct acc_dev *dev;
	unsigned long flags;

	spin_lock_irqsave(&acc_dev_instance_lock, flags);
	dev = acc_dev_instance;
	if (dev && (READ_ONCE(dev->closing) ||
		    !kref_get_unless_zero(&dev->kref)))
		dev = NULL;
	spin_unlock_irqrestore(&acc_dev_instance_lock, flags);

	return dev;
}

static void acc_dev_release_work(struct work_struct *work)
{
	struct acc_dev *dev = container_of(work, struct acc_dev, release_work);
	unsigned long flags;

	/* The last reference may be dropped in interrupt context or hid_work. */
	cancel_delayed_work_sync(&dev->start_work);
	cancel_work_sync(&dev->getprotocol_work);
	cancel_work_sync(&dev->sendstring_work);
	cancel_work_sync(&dev->hid_work);
	put_device(dev->device);

	/* Keep the singleton reserved until its old workers have stopped. */
	spin_lock_irqsave(&acc_dev_instance_lock, flags);
	acc_dev_instance = NULL;
	spin_unlock_irqrestore(&acc_dev_instance_lock, flags);
	kfree(dev);
}

static void __acc_dev_instance_release(struct kref *kref)
{
	struct acc_dev *dev = container_of(kref, struct acc_dev, kref);

	schedule_work(&dev->release_work);
}

static void put_acc_dev(struct acc_dev *dev)
{
	kref_put(&dev->kref, __acc_dev_instance_release);
}

static void acc_hid_release_work(struct work_struct *work)
{
	struct acc_hid_dev *hid = container_of(work, struct acc_hid_dev, release_work);
	struct acc_dev *dev = hid->dev;
	unsigned long flags;

	if (hid->hid)
		hid_destroy_device(hid->hid);
	kfree(hid->report_desc);
	kfree(hid);
	spin_lock_irqsave(&dev->lock, flags);
	dev->hid_count--;
	spin_unlock_irqrestore(&dev->lock, flags);
	put_acc_dev(dev);
}

static void acc_hid_release(struct kref *kref)
{
	struct acc_hid_dev *hid = container_of(kref, struct acc_hid_dev, kref);

	schedule_work(&hid->release_work);
}

static void acc_hid_put(struct acc_hid_dev *hid)
{
	kref_put(&hid->kref, acc_hid_release);
}

static void acc_control_put(struct acc_control_request *control)
{
	if (control->hid)
		acc_hid_put(control->hid);
	put_acc_dev(control->dev);
	kfree(control);
}

static void acc_complete_control(struct usb_ep *ep, struct usb_request *req)
{
	struct acc_control_request *control = req->context;

	control->complete(ep, req);
	req->context = NULL;
	acc_control_put(control);
}

static inline struct acc_dev *func_to_dev(struct usb_function *f)
{
	return container_of(f, struct acc_dev, function);
}

static struct usb_request *acc_request_new(struct usb_ep *ep, int buffer_size)
{
	struct usb_request *req = usb_ep_alloc_request(ep, GFP_KERNEL);

	if (!req)
		return NULL;

	/* now allocate buffers for the requests */
	req->buf = kmalloc(buffer_size, GFP_KERNEL);
	if (!req->buf) {
		usb_ep_free_request(ep, req);
		return NULL;
	}

	return req;
}

static void acc_request_free(struct usb_request *req, struct usb_ep *ep)
{
	if (req) {
		kfree(req->buf);
		usb_ep_free_request(ep, req);
	}
}

/* add a request to the tail of a list */
static void req_put(struct acc_dev *dev, struct list_head *head,
		struct usb_request *req)
{
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_add_tail(&req->list, head);
	spin_unlock_irqrestore(&dev->lock, flags);
}

/* remove a request from the head of a list */
static struct usb_request *req_get(struct acc_dev *dev, struct list_head *head)
{
	unsigned long flags;
	struct usb_request *req;

	spin_lock_irqsave(&dev->lock, flags);
	if (list_empty(head)) {
		req = 0;
	} else {
		req = list_first_entry(head, struct usb_request, list);
		list_del(&req->list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
	return req;
}

static void acc_free_all_requests(struct acc_dev *dev)
{
	struct usb_request *req;
	int i;

	while ((req = req_get(dev, &dev->tx_idle)))
		acc_request_free(req, dev->ep_in);
	for (i = 0; i < RX_REQ_MAX; i++) {
		acc_request_free(dev->rx_req[i], dev->ep_out);
		dev->rx_req[i] = NULL;
	}
}

static void acc_complete_in(struct usb_ep *ep, struct usb_request *req)
{
	struct acc_dev *dev = get_acc_dev();

	if (!dev)
		return;

	if (req->status == -ESHUTDOWN) {
		pr_debug("set disconnected\n");
		dev->disconnected = true;
	}

	req_put(dev, &dev->tx_idle, req);

	wake_up(&dev->write_wq);
	put_acc_dev(dev);
}

static void acc_complete_out(struct usb_ep *ep, struct usb_request *req)
{
	struct acc_dev *dev = get_acc_dev();

	if (!dev)
		return;

	dev->rx_done = 1;
	if (req->status == -ESHUTDOWN) {
		pr_debug("set disconnected\n");
		dev->disconnected = true;
	}

	wake_up(&dev->read_wq);
	put_acc_dev(dev);
}

static void acc_complete_set_string(struct usb_ep *ep, struct usb_request *req)
{
	struct acc_control_request *control = req->context;
	struct acc_dev *dev = control->dev;
	char *string_dest = NULL;
	int length = req->actual;

	if (req->status != 0) {
		pr_err("err %d\n", req->status);
		return;
	}

	switch (control->index) {
	case ACCESSORY_STRING_MANUFACTURER:
		string_dest = dev->manufacturer;
		break;
	case ACCESSORY_STRING_MODEL:
		string_dest = dev->model;
		break;
	case ACCESSORY_STRING_DESCRIPTION:
		string_dest = dev->description;
		break;
	case ACCESSORY_STRING_VERSION:
		string_dest = dev->version;
		break;
	case ACCESSORY_STRING_URI:
		string_dest = dev->uri;
		break;
	case ACCESSORY_STRING_SERIAL:
		string_dest = dev->serial;
		break;
	}
	if (string_dest) {
		unsigned long flags;

		if (length >= ACC_STRING_SIZE)
			length = ACC_STRING_SIZE - 1;

		spin_lock_irqsave(&dev->lock, flags);
		if (dev->closing) {
			spin_unlock_irqrestore(&dev->lock, flags);
			return;
		}
		memcpy(string_dest, req->buf, length);
		/* ensure zero termination */
		string_dest[length] = 0;
		spin_unlock_irqrestore(&dev->lock, flags);
	} else {
		pr_err("unknown accessory string index %d\n",
			control->index);
	}
}

static void acc_complete_set_hid_report_desc(struct usb_ep *ep,
		struct usb_request *req)
{
	struct acc_control_request *control = req->context;
	struct acc_hid_dev *hid = control->hid;
	struct acc_dev *dev = control->dev;
	unsigned long flags;

	if (req->status)
		return;

	spin_lock_irqsave(&dev->lock, flags);
	if (!dev->closing && !hid->dead && !hid->initializing &&
	    control->index == hid->report_desc_offset &&
	    req->actual <= control->length &&
	    req->actual <= hid->report_desc_len - hid->report_desc_offset) {
		memcpy(hid->report_desc + hid->report_desc_offset,
		       req->buf, req->actual);
		hid->report_desc_offset += req->actual;
		if (hid->report_desc_offset == hid->report_desc_len)
			schedule_work(&dev->hid_work);
	}
	spin_unlock_irqrestore(&dev->lock, flags);
}

static void acc_complete_send_hid_event(struct usb_ep *ep,
		struct usb_request *req)
{
	struct acc_control_request *control = req->context;
	struct acc_hid_dev *hid = control->hid;
	int length = req->actual;

	if (req->status != 0) {
		pr_err("err %d\n", req->status);
		return;
	}
	if (READ_ONCE(control->dev->closing) || READ_ONCE(hid->dead) ||
	    req->actual > control->length)
		return;

	/* Serialize delivery with native HID probe/remove and input quiescing. */
	hid_safe_input_report(hid->hid, HID_INPUT_REPORT, req->buf, length, length, 1);
}

static int acc_hid_parse(struct hid_device *hid)
{
	struct acc_hid_dev *hdev = hid->driver_data;

	return hid_parse_report(hid, hdev->report_desc, hdev->report_desc_len);
}

// Required by the hid_ll_driver, so do nothing.
static int acc_hid_start(struct hid_device *hid)
{
	return 0;
}

// Required by the hid_ll_driver, so do nothing.
static void acc_hid_stop(struct hid_device *hid)
{
}

// Required by the hid_ll_driver, so do nothing.
static int acc_hid_open(struct hid_device *hid)
{
	return 0;
}

// Required by the hid_ll_driver, so do nothing.
static void acc_hid_close(struct hid_device *hid)
{
}

static int acc_hid_raw_request(struct hid_device *hid, unsigned char reportnum,
	__u8 *buf, size_t len, unsigned char rtype, int reqtype)
{
	return 0;
}

static struct hid_ll_driver acc_hid_ll_driver = {
	.parse = acc_hid_parse,
	.start = acc_hid_start,
	.stop = acc_hid_stop,
	.open = acc_hid_open,
	.close = acc_hid_close,
	.raw_request = acc_hid_raw_request,
	.max_buffer_size = USB_COMP_EP0_BUFSIZ,
};

static struct acc_hid_dev *acc_hid_new(struct acc_dev *dev,
		int id, int desc_len)
{
	struct acc_hid_dev *hdev;

	hdev = kzalloc(sizeof(*hdev), GFP_ATOMIC);
	if (!hdev)
		return NULL;
	hdev->report_desc = kzalloc(desc_len, GFP_ATOMIC);
	if (!hdev->report_desc) {
		kfree(hdev);
		return NULL;
	}
	kref_init(&hdev->kref);
	INIT_WORK(&hdev->release_work, acc_hid_release_work);
	kref_get(&dev->kref);
	dev->hid_count++;
	hdev->dev = dev;
	hdev->id = id;
	hdev->report_desc_len = desc_len;

	return hdev;
}

/** acc_hid_get_locked - a helper function to walk a list of hid devices and
 * return a pointer to the acc_hid_dev which matches the id argument which
 * matches the id argument.
 *
 * @list - the list of devices to search through
 * @id - the id of the acc_hid_dev to find
 *
 * The caller of this function must protect the list by locking the
 * acc_dev->lock prior to calling this function.
 *
 * Returns: a pointer to the acc_hid_dev with the specified id or NULL if that
 * id is not found in the list.
 */
static struct acc_hid_dev *acc_hid_get_locked(struct list_head *list, int id)
{
	struct acc_hid_dev *hid;

	list_for_each_entry(hid, list, list) {
		if (hid->id == id)
			return hid;
	}
	return NULL;
}

/* Caller holds dev->lock. */
static int acc_register_hid(struct acc_dev *dev, int id, int desc_length)
{
	struct acc_hid_dev *hid, *old;

	if (desc_length <= 0 || desc_length > MAX_HID_DESC_SIZE ||
	    id <= 0 || id > MAX_HID_DEVICES)
		return -EINVAL;
	if (dev->hid_count >= MAX_HID_ALLOCATIONS)
		return -EBUSY;

	/* Do not retire a working device if replacement allocation fails. */
	hid = acc_hid_new(dev, id, desc_length);
	if (!hid)
		return -ENOMEM;
	old = acc_hid_get_locked(&dev->hid_list, id);
	if (!old)
		old = acc_hid_get_locked(&dev->new_hid_list, id);
	if (old) {
		WRITE_ONCE(old->dead, true);
		list_move(&old->list, &dev->dead_hid_list);
	}
	list_add(&hid->list, &dev->new_hid_list);
	schedule_work(&dev->hid_work);
	return 0;
}

/* Caller holds dev->lock. */
static int acc_unregister_hid(struct acc_dev *dev, int id)
{
	struct acc_hid_dev *hid;

	hid = acc_hid_get_locked(&dev->hid_list, id);
	if (!hid)
		hid = acc_hid_get_locked(&dev->new_hid_list, id);
	if (!hid)
		return -EINVAL;

	WRITE_ONCE(hid->dead, true);
	list_move(&hid->list, &dev->dead_hid_list);
	schedule_work(&dev->hid_work);
	return 0;
}

static int create_bulk_endpoints(struct acc_dev *dev,
				struct usb_endpoint_descriptor *in_desc,
				struct usb_endpoint_descriptor *out_desc)
{
	struct usb_composite_dev *cdev = dev->cdev;
	struct usb_request *req;
	struct usb_ep *ep;
	int i;

	DBG(cdev, "dev: %p\n", dev);

	ep = usb_ep_autoconfig(cdev->gadget, in_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_in failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_in got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_in = ep;

	ep = usb_ep_autoconfig(cdev->gadget, out_desc);
	if (!ep) {
		DBG(cdev, "usb_ep_autoconfig for ep_out failed\n");
		return -ENODEV;
	}
	DBG(cdev, "usb_ep_autoconfig for ep_out got %s\n", ep->name);
	ep->driver_data = dev;		/* claim the endpoint */
	dev->ep_out = ep;

	/* now allocate requests for our endpoints */
	for (i = 0; i < TX_REQ_MAX; i++) {
		req = acc_request_new(dev->ep_in, BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = acc_complete_in;
		req_put(dev, &dev->tx_idle, req);
	}
	for (i = 0; i < RX_REQ_MAX; i++) {
		req = acc_request_new(dev->ep_out, BULK_BUFFER_SIZE);
		if (!req)
			goto fail;
		req->complete = acc_complete_out;
		dev->rx_req[i] = req;
	}

	return 0;

fail:
	pr_err("could not allocate requests\n");
	acc_free_all_requests(dev);

	return -1;
}

static ssize_t acc_read(struct file *fp, char __user *buf,
	size_t count, loff_t *pos)
{
	struct acc_dev *dev = fp->private_data;
	struct usb_request *req;
	ssize_t r = count;
	ssize_t data_length;
	unsigned int xfer;
	int ret = 0;

	if (dev->disconnected) {
		pr_debug("disconnected\n");
		return -ENODEV;
	}

	if (count > BULK_BUFFER_SIZE)
		count = BULK_BUFFER_SIZE;

	/* we will block until we're online */
	pr_debug("waiting for online\n");
	ret = wait_event_interruptible(dev->read_wq, dev->online);
	if (ret < 0) {
		r = ret;
		goto done;
	}

	if (!dev->rx_req[0]) {
		pr_debug("USB request already handled/freed\n");
		r = -EINVAL;
		goto done;
	}

	/*
	 * Calculate the data length by considering termination character.
	 * Then compansite the difference of rounding up to
	 * integer multiple of maxpacket size.
	 */
	data_length = count;
	data_length += dev->ep_out->maxpacket - 1;
	data_length -= data_length % dev->ep_out->maxpacket;

	if (dev->rx_done) {
		// last req cancelled. try to get it.
		req = dev->rx_req[0];
		goto copy_data;
	}

requeue_req:
	/* queue a request */
	req = dev->rx_req[0];
	req->length = data_length;
	dev->rx_done = 0;
	ret = usb_ep_queue(dev->ep_out, req, GFP_KERNEL);
	if (ret < 0) {
		r = -EIO;
		goto done;
	} else {
		pr_debug("rx %p queue\n", req);
	}

	/* wait for a request to complete */
	ret = wait_event_interruptible(dev->read_wq, dev->rx_done);
	if (ret < 0) {
		r = ret;
		ret = usb_ep_dequeue(dev->ep_out, req);
		if (ret != 0) {
			// cancel failed. There can be a data already received.
			// it will be retrieved in the next read.
			pr_debug("cancelling failed %d\n", ret);
		}
		goto done;
	}

copy_data:
	dev->rx_done = 0;
	if (dev->online) {
		/* If we got a 0-len packet, throw it back and try again. */
		if (req->actual == 0)
			goto requeue_req;

		pr_debug("rx %p %u\n", req, req->actual);
		xfer = (req->actual < count) ? req->actual : count;
		r = xfer;
		if (copy_to_user(buf, req->buf, xfer))
			r = -EFAULT;
	} else
		r = -EIO;

done:
	pr_debug("returning %zd\n", r);
	return r;
}

static ssize_t acc_write(struct file *fp, const char __user *buf,
	size_t count, loff_t *pos)
{
	struct acc_dev *dev = fp->private_data;
	struct usb_request *req = 0;
	ssize_t r = count;
	unsigned int xfer;
	int ret;

	if (!dev->online || dev->disconnected) {
		pr_debug("disconnected or not online\n");
		return -ENODEV;
	}

	while (count > 0) {
		/* get an idle tx request to use */
		req = 0;
		ret = wait_event_interruptible(dev->write_wq,
			((req = req_get(dev, &dev->tx_idle)) || !dev->online));
		if (!dev->online || dev->disconnected) {
			pr_debug("dev->error\n");
			r = -EIO;
			break;
		}

		if (!req) {
			r = ret;
			break;
		}

		if (count > BULK_BUFFER_SIZE) {
			xfer = BULK_BUFFER_SIZE;
			/* ZLP, They will be more TX requests so not yet. */
			req->zero = 0;
		} else {
			xfer = count;
			/* If the data length is a multiple of the
			 * maxpacket size then send a zero length packet(ZLP).
			 */
			req->zero = ((xfer % dev->ep_in->maxpacket) == 0);
		}
		if (copy_from_user(req->buf, buf, xfer)) {
			r = -EFAULT;
			break;
		}

		req->length = xfer;
		ret = usb_ep_queue(dev->ep_in, req, GFP_KERNEL);
		if (ret < 0) {
			pr_debug("xfer error %d\n", ret);
			r = -EIO;
			break;
		}

		buf += xfer;
		count -= xfer;

		/* zero this so we don't try to free it on error exit */
		req = 0;
	}

	if (req)
		req_put(dev, &dev->tx_idle, req);

	pr_debug("returning %zd\n", r);
	return r;
}

static long acc_ioctl(struct file *fp, unsigned int code, unsigned long value)
{
	struct acc_dev *dev = fp->private_data;
	char *src = NULL;
	int ret;

	switch (code) {
	case ACCESSORY_GET_STRING_MANUFACTURER:
		src = dev->manufacturer;
		break;
	case ACCESSORY_GET_STRING_MODEL:
		src = dev->model;
		break;
	case ACCESSORY_GET_STRING_DESCRIPTION:
		src = dev->description;
		break;
	case ACCESSORY_GET_STRING_VERSION:
		src = dev->version;
		break;
	case ACCESSORY_GET_STRING_URI:
		src = dev->uri;
		break;
	case ACCESSORY_GET_STRING_SERIAL:
		src = dev->serial;
		break;
	case ACCESSORY_IS_START_REQUESTED:
		return dev->start_requested;
	case ACCESSORY_GET_AUDIO_MODE:
		return dev->audio_mode;
	}
	if (!src)
		return -ENOTTY;

	ret = strlen(src) + 1;
	if (copy_to_user((void __user *)value, src, ret))
		ret = -EFAULT;
	return ret;
}

static int acc_open(struct inode *ip, struct file *fp)
{
	struct acc_dev *dev = get_acc_dev();

	if (!dev)
		return -ENODEV;

	dev->disconnected = false;
	fp->private_data = dev;
	return 0;
}

static int acc_release(struct inode *ip, struct file *fp)
{
	struct acc_dev *dev = fp->private_data;

	if (!dev)
		return -ENOENT;

	/* indicate that we are disconnected
	 * still could be online so don't touch online flag
	 */
	dev->disconnected = true;

	fp->private_data = NULL;
	put_acc_dev(dev);
	return 0;
}

/* file operations for /dev/usb_accessory */
static const struct file_operations acc_fops = {
	.owner = THIS_MODULE,
	.read = acc_read,
	.write = acc_write,
	.unlocked_ioctl = acc_ioctl,
	.compat_ioctl = acc_ioctl,
	.open = acc_open,
	.release = acc_release,
};

static int acc_hid_probe(struct hid_device *hdev,
		const struct hid_device_id *id)
{
	int ret;

	ret = hid_parse(hdev);
	if (ret)
		return ret;
	return hid_hw_start(hdev, HID_CONNECT_DEFAULT);
}

static struct miscdevice acc_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "usb_accessory",
	.fops = &acc_fops,
};

static const struct hid_device_id acc_hid_table[] = {
	{ HID_USB_DEVICE(HID_ANY_ID, HID_ANY_ID) },
	{ }
};

static struct hid_driver acc_hid_driver = {
	.name = "USB accessory",
	.id_table = acc_hid_table,
	.probe = acc_hid_probe,
};

static void acc_complete_setup_noop(struct usb_ep *ep, struct usb_request *req)
{
	/*
	 * Default no-op function when nothing needs to be done for the
	 * setup request
	 */
}

static int __acc_function_bind(struct usb_configuration *c,
		struct usb_function *f, bool configfs)
{
	struct usb_composite_dev *cdev = c->cdev;
	struct usb_string *us;
	struct acc_dev *dev = func_to_dev(f);
	int id;
	int ret;

	if (configfs) {
		us = usb_gstrings_attach(cdev, acc_strings,
				ARRAY_SIZE(acc_string_defs));
		if (IS_ERR(us))
			return PTR_ERR(us);
		ret = us[INTERFACE_STRING_INDEX].id;
		acc_interface_desc.iInterface = ret;
		dev->cdev = c->cdev;
	}
	dev->start_requested = 0;

	/* allocate interface ID(s) */
	id = usb_interface_id(c, f);
	if (id < 0)
		return id;
	acc_interface_desc.bInterfaceNumber = id;

	/* allocate endpoints */
	ret = create_bulk_endpoints(dev, &acc_fullspeed_in_desc,
			&acc_fullspeed_out_desc);
	if (ret)
		return ret;

	/* support high speed hardware */
	acc_highspeed_in_desc.bEndpointAddress =
		acc_fullspeed_in_desc.bEndpointAddress;
	acc_highspeed_out_desc.bEndpointAddress =
		acc_fullspeed_out_desc.bEndpointAddress;

	/* support super speed hardware */
	acc_superspeed_in_desc.bEndpointAddress =
		acc_fullspeed_in_desc.bEndpointAddress;
	acc_superspeed_out_desc.bEndpointAddress =
		acc_fullspeed_out_desc.bEndpointAddress;

	/* support super speed plus hardware */
	acc_superspeedplus_in_desc.bEndpointAddress =
		acc_fullspeed_in_desc.bEndpointAddress;
	acc_superspeedplus_out_desc.bEndpointAddress =
		acc_fullspeed_out_desc.bEndpointAddress;

	ret = hid_register_driver(&acc_hid_driver);
	if (ret) {
		/* Cleanup requests allocated in create_bulk_endpoints() */
		acc_free_all_requests(dev);
		return ret;
	}

	DBG(cdev, "%s speed %s: IN/%s, OUT/%s\n",
			gadget_is_dualspeed(c->cdev->gadget) ? "dual" : "full",
			f->name, dev->ep_in->name, dev->ep_out->name);

	return 0;
}

static int acc_function_bind_configfs(struct usb_configuration *c,
			struct usb_function *f)
{
	return __acc_function_bind(c, f, true);
}

static void kill_all_hid_devices(struct acc_dev *dev)
{
	struct acc_hid_dev *hid;
	struct list_head *entry, *temp;
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	list_for_each_safe(entry, temp, &dev->hid_list) {
		hid = list_entry(entry, struct acc_hid_dev, list);
		WRITE_ONCE(hid->dead, true);
		list_del(&hid->list);
		list_add(&hid->list, &dev->dead_hid_list);
	}
	list_for_each_safe(entry, temp, &dev->new_hid_list) {
		hid = list_entry(entry, struct acc_hid_dev, list);
		WRITE_ONCE(hid->dead, true);
		list_del(&hid->list);
		list_add(&hid->list, &dev->dead_hid_list);
	}
	spin_unlock_irqrestore(&dev->lock, flags);

	schedule_work(&dev->hid_work);
}

static void acc_hid_unbind(struct acc_dev *dev)
{
	hid_unregister_driver(&acc_hid_driver);
	kill_all_hid_devices(dev);
}

static void acc_function_unbind(struct usb_configuration *c,
		struct usb_function *f)
{
	struct acc_dev *dev = func_to_dev(f);

	dev->online = false;		/* clear online flag */
	wake_up(&dev->read_wq);		/* unblock reads on closure */
	wake_up(&dev->write_wq);	/* likewise for writes */

	acc_free_all_requests(dev);

	acc_hid_unbind(dev);
}

static void acc_getprotocol_work(struct work_struct *data)
{
	struct acc_dev *dev = container_of(data, struct acc_dev, getprotocol_work);
	char *envp[2] = { "ACCESSORY=GETPROTOCOL", NULL };

	kobject_uevent_env(&dev->device->kobj, KOBJ_CHANGE, envp);
}

static void acc_sendstring_work(struct work_struct *data)
{
	struct acc_dev *dev = container_of(data, struct acc_dev, sendstring_work);
	char *envp[2] = { "ACCESSORY=SENDSTRING", NULL };

	kobject_uevent_env(&dev->device->kobj, KOBJ_CHANGE, envp);
}

static void acc_start_work(struct work_struct *data)
{
	struct acc_dev *dev = container_of(data, struct acc_dev, start_work.work);
	char *envp[2] = { "ACCESSORY=START", NULL };

	kobject_uevent_env(&dev->device->kobj, KOBJ_CHANGE, envp);
}

static int acc_hid_init(struct acc_hid_dev *hdev)
{
	struct hid_device *hid;
	int ret;

	hid = hid_allocate_device();
	if (IS_ERR(hid))
		return PTR_ERR(hid);

	hid->ll_driver = &acc_hid_ll_driver;
	hid->dev.parent = hdev->dev->device;

	hid->bus = BUS_USB;
	hid->vendor = HID_ANY_ID;
	hid->product = HID_ANY_ID;
	hid->driver_data = hdev;
	ret = hid_add_device(hid);
	if (ret) {
		pr_err("can't add hid device: %d\n", ret);
		hid_destroy_device(hid);
		return ret;
	}

	hdev->hid = hid;
	return 0;
}

static void acc_hid_work(struct work_struct *data)
{
	struct acc_dev *dev = container_of(data, struct acc_dev, hid_work);
	struct acc_hid_dev *hid, *next;
	unsigned long flags;
	int ret;

	for (;;) {
		spin_lock_irqsave(&dev->lock, flags);
		if (!list_empty(&dev->dead_hid_list)) {
			hid = list_first_entry(&dev->dead_hid_list,
					       struct acc_hid_dev, list);
			list_del_init(&hid->list);
			spin_unlock_irqrestore(&dev->lock, flags);
			acc_hid_put(hid);
			continue;
		}

		hid = NULL;
		list_for_each_entry(next, &dev->new_hid_list, list) {
			if (next->report_desc_offset == next->report_desc_len) {
				hid = next;
				break;
			}
		}
		if (!hid) {
			spin_unlock_irqrestore(&dev->lock, flags);
			break;
		}
		/* Stay visible to disconnect and ID replacement during init. */
		hid->initializing = true;
		kref_get(&hid->kref);
		spin_unlock_irqrestore(&dev->lock, flags);

		ret = acc_hid_init(hid);

		spin_lock_irqsave(&dev->lock, flags);
		hid->initializing = false;
		if (!hid->dead) {
			if (ret) {
				WRITE_ONCE(hid->dead, true);
				list_move(&hid->list, &dev->dead_hid_list);
			} else {
				list_move(&hid->list, &dev->hid_list);
			}
		}
		spin_unlock_irqrestore(&dev->lock, flags);
		acc_hid_put(hid);
	}
}

static int acc_function_set_alt(struct usb_function *f,
		unsigned int intf, unsigned int alt)
{
	struct acc_dev *dev = func_to_dev(f);
	struct usb_composite_dev *cdev = f->config->cdev;
	int ret;

	DBG(cdev, "intf: %d alt: %d\n", intf, alt);

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_in);
	if (ret)
		return ret;

	ret = usb_ep_enable(dev->ep_in);
	if (ret)
		return ret;

	ret = config_ep_by_speed(cdev->gadget, f, dev->ep_out);
	if (ret)
		return ret;

	ret = usb_ep_enable(dev->ep_out);
	if (ret) {
		usb_ep_disable(dev->ep_in);
		return ret;
	}

	dev->online = true;
	dev->disconnected = false; /* if online then not disconnected */

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);
	return 0;
}

static void acc_function_disable(struct usb_function *f)
{
	struct acc_dev *dev = func_to_dev(f);
	struct usb_composite_dev *cdev = dev->cdev;

	dev->disconnected = true;
	dev->online = false; /* so now need to clear online flag here too */
	usb_ep_disable(dev->ep_in);
	usb_ep_disable(dev->ep_out);

	/* readers may be blocked waiting for us to go online */
	wake_up(&dev->read_wq);

	DBG(cdev, "%s disabled\n", dev->function.name);
}

static int acc_init(void)
{
	struct acc_dev *dev;
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&acc_dev_instance_lock, flags);
	if (acc_dev_instance || acc_dev_instance_creating) {
		spin_unlock_irqrestore(&acc_dev_instance_lock, flags);
		return -EBUSY;
	}
	acc_dev_instance_creating = true;
	spin_unlock_irqrestore(&acc_dev_instance_lock, flags);

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		ret = -ENOMEM;
		goto err_clear_creating;
	}

	spin_lock_init(&dev->lock);
	init_waitqueue_head(&dev->read_wq);
	init_waitqueue_head(&dev->write_wq);
	INIT_LIST_HEAD(&dev->tx_idle);
	INIT_LIST_HEAD(&dev->hid_list);
	INIT_LIST_HEAD(&dev->new_hid_list);
	INIT_LIST_HEAD(&dev->dead_hid_list);
	INIT_DELAYED_WORK(&dev->start_work, acc_start_work);
	INIT_WORK(&dev->hid_work, acc_hid_work);
	INIT_WORK(&dev->getprotocol_work, acc_getprotocol_work);
	INIT_WORK(&dev->sendstring_work, acc_sendstring_work);
	INIT_WORK(&dev->release_work, acc_dev_release_work);

	kref_init(&dev->kref);

	ret = misc_register(&acc_device);
	if (ret)
		goto err_free_dev;

	dev->device = get_device(acc_device.this_device);

	/* A failed registration must never expose an object to get_acc_dev(). */
	spin_lock_irqsave(&acc_dev_instance_lock, flags);
	acc_dev_instance = dev;
	acc_dev_instance_creating = false;
	spin_unlock_irqrestore(&acc_dev_instance_lock, flags);
	return 0;

err_free_dev:
	kfree(dev);
err_clear_creating:
	spin_lock_irqsave(&acc_dev_instance_lock, flags);
	acc_dev_instance_creating = false;
	spin_unlock_irqrestore(&acc_dev_instance_lock, flags);
	pr_err("USB accessory gadget driver failed to initialize\n");
	return ret;
}

void android_acc_disconnect(void)
{
	struct acc_dev *dev = get_acc_dev();

	if (!dev)
		return;

	/* unregister all HID devices if USB is disconnected */
	kill_all_hid_devices(dev);
	put_acc_dev(dev);
}

static void acc_cleanup(void)
{
	struct acc_dev *dev = get_acc_dev();
	unsigned long flags;

	spin_lock_irqsave(&dev->lock, flags);
	WRITE_ONCE(dev->closing, true);
	spin_unlock_irqrestore(&dev->lock, flags);

	/* Every control producer checks closing under dev->lock. */
	cancel_delayed_work_sync(&dev->start_work);
	cancel_work_sync(&dev->getprotocol_work);
	cancel_work_sync(&dev->sendstring_work);
	kill_all_hid_devices(dev);
	flush_work(&dev->hid_work);
	misc_deregister(&acc_device);
	put_acc_dev(dev);
	put_acc_dev(dev); /* Pairs with kref_init() in acc_init() */
}
static struct acc_instance *to_acc_instance(struct config_item *item)
{
	return container_of(to_config_group(item), struct acc_instance,
		func_inst.group);
}

static void acc_attr_release(struct config_item *item)
{
	struct acc_instance *fi_acc = to_acc_instance(item);

	usb_put_function_instance(&fi_acc->func_inst);
}

static struct configfs_item_operations acc_item_ops = {
	.release        = acc_attr_release,
};

static struct config_item_type acc_func_type = {
	.ct_item_ops    = &acc_item_ops,
	.ct_owner       = THIS_MODULE,
};

static struct acc_instance *to_fi_acc(struct usb_function_instance *fi)
{
	return container_of(fi, struct acc_instance, func_inst);
}

static int acc_set_inst_name(struct usb_function_instance *fi,
		const char *name)
{
	struct acc_instance *fi_acc;
	char *ptr;
	int name_len;

	name_len = strlen(name) + 1;
	if (name_len > MAX_INST_NAME_LEN)
		return -ENAMETOOLONG;

	ptr = kstrndup(name, name_len, GFP_KERNEL);
	if (!ptr)
		return -ENOMEM;

	fi_acc = to_fi_acc(fi);
	fi_acc->name = ptr;
	return 0;
}

static void acc_free_inst(struct usb_function_instance *fi)
{
	struct acc_instance *fi_acc;

	fi_acc = to_fi_acc(fi);
	kfree(fi_acc->name);
	acc_cleanup();
	kfree(fi_acc);
}

static struct usb_function_instance *acc_alloc_inst(void)
{
	struct acc_instance *fi_acc;
	int err;

	fi_acc = kzalloc(sizeof(*fi_acc), GFP_KERNEL);
	if (!fi_acc)
		return ERR_PTR(-ENOMEM);
	fi_acc->func_inst.set_inst_name = acc_set_inst_name;
	fi_acc->func_inst.free_func_inst = acc_free_inst;

	err = acc_init();
	if (err) {
		kfree(fi_acc);
		return ERR_PTR(err);
	}

	config_group_init_type_name(&fi_acc->func_inst.group,
					"", &acc_func_type);
	return  &fi_acc->func_inst;
}

static void acc_free(struct usb_function *f)
{
	struct acc_dev *dev = func_to_dev(f);

	put_acc_dev(dev);
}

static bool __acc_req_match(const struct usb_ctrlrequest *ctrl)
{
	struct acc_dev *dev = get_acc_dev();
	u8 bRequestType = ctrl->bRequestType;
	u8 bRequest = ctrl->bRequest;
	bool ret = false;

	/*
	 * If instance is not created which is the case in power off charging
	 * mode, dev will be NULL. Hence return error if it is the case.
	 */
	if (!dev)
		return false;

	if (bRequestType == (USB_DIR_OUT | USB_TYPE_VENDOR)) {
		switch (bRequest) {
		case ACCESSORY_START:
		case ACCESSORY_SEND_STRING:
		case ACCESSORY_SET_AUDIO_MODE:
		case ACCESSORY_REGISTER_HID:
		case ACCESSORY_UNREGISTER_HID:
		case ACCESSORY_SET_HID_REPORT_DESC:
		case ACCESSORY_SEND_HID_EVENT:
			ret = true;
			break;
		default:
			ret = false;
		}
	} else if ((bRequestType == (USB_DIR_IN | USB_TYPE_VENDOR)) &&
			(bRequest == ACCESSORY_GET_PROTOCOL))
		ret = true;

	put_acc_dev(dev);
	return ret;
}

static bool acc_req_match(struct usb_function *f,
		const struct usb_ctrlrequest *ctrl, bool config)
{
	return __acc_req_match(ctrl);
}

bool android_acc_req_match_composite(struct usb_composite_dev *cdev,
		const struct usb_ctrlrequest *ctrl)
{
	return __acc_req_match(ctrl);
}

static int __acc_setup(struct usb_composite_dev *cdev,
		const struct usb_ctrlrequest *ctrl)
{
	struct acc_dev *dev = get_acc_dev();
	int value = -EOPNOTSUPP;
	struct acc_hid_dev *hid;
	struct acc_control_request *control;
	u8 bRequestType = ctrl->bRequestType;
	u8 bRequest = ctrl->bRequest;
	u16 wIndex = le16_to_cpu(ctrl->wIndex);
	u16 wValue = le16_to_cpu(ctrl->wValue);
	u16 wLength = le16_to_cpu(ctrl->wLength);
	unsigned long flags;

	/*
	 * If instance is not created which is the case in power off charging
	 * mode, dev will be NULL. Hence return error if it is the case.
	 */
	if (!dev)
		return -ENODEV;

	control = kzalloc(sizeof(*control), GFP_ATOMIC);
	if (!control) {
		put_acc_dev(dev);
		return -ENOMEM;
	}
	control->dev = dev;
	control->index = wIndex;
	control->length = wLength;
	/* Separate setup and queued-completion ownership. */
	kref_get(&dev->kref);
	cdev->req->context = control;
	cdev->req->complete = acc_complete_setup_noop;

	spin_lock_irqsave(&dev->lock, flags);
	if (dev->closing) {
		value = -ENODEV;
		goto unlock;
	}

	if (bRequestType == (USB_DIR_OUT | USB_TYPE_VENDOR)) {
		if (bRequest == ACCESSORY_START) {
			dev->start_requested = 1;
			schedule_delayed_work(
				&dev->start_work, msecs_to_jiffies(10));
			value = 0;
			cdev->req->complete = acc_complete_setup_noop;
		} else if (bRequest == ACCESSORY_SEND_STRING) {
			schedule_work(&dev->sendstring_work);
			cdev->req->complete = acc_complete_set_string;
			value = wLength;
		} else if (bRequest == ACCESSORY_SET_AUDIO_MODE &&
				wIndex == 0 && wLength == 0) {
			dev->audio_mode = wValue;
			cdev->req->complete = acc_complete_setup_noop;
			value = 0;
		} else if (bRequest == ACCESSORY_REGISTER_HID) {
			cdev->req->complete = acc_complete_setup_noop;
			value = acc_register_hid(dev, wValue, wIndex);
		} else if (bRequest == ACCESSORY_UNREGISTER_HID) {
			cdev->req->complete = acc_complete_setup_noop;
			value = acc_unregister_hid(dev, wValue);
		} else if (bRequest == ACCESSORY_SET_HID_REPORT_DESC) {
			hid = acc_hid_get_locked(&dev->new_hid_list, wValue);
			if (!hid) {
				value = -EINVAL;
				goto unlock;
			}
			if (hid->initializing || wIndex != hid->report_desc_offset ||
			    wIndex + wLength > hid->report_desc_len) {
				value = -EINVAL;
				goto unlock;
			}
			kref_get(&hid->kref);
			control->hid = hid;
			cdev->req->complete = acc_complete_set_hid_report_desc;
			value = wLength;
		} else if (bRequest == ACCESSORY_SEND_HID_EVENT) {
			hid = acc_hid_get_locked(&dev->hid_list, wValue);
			if (!hid) {
				value = -EINVAL;
				goto unlock;
			}
			kref_get(&hid->kref);
			control->hid = hid;
			cdev->req->complete = acc_complete_send_hid_event;
			value = wLength;
		}
	} else if (bRequestType == (USB_DIR_IN | USB_TYPE_VENDOR)) {
		if (bRequest == ACCESSORY_GET_PROTOCOL) {
			schedule_work(&dev->getprotocol_work);
			*((u16 *)cdev->req->buf) = PROTOCOL_VERSION;
			value = sizeof(u16);
			cdev->req->complete = acc_complete_setup_noop;
			/* clear strings left over from a previous session */
			memset(dev->manufacturer, 0,
					sizeof(dev->manufacturer));
			memset(dev->model, 0, sizeof(dev->model));
			memset(dev->description, 0, sizeof(dev->description));
			memset(dev->version, 0, sizeof(dev->version));
			memset(dev->uri, 0, sizeof(dev->uri));
			memset(dev->serial, 0, sizeof(dev->serial));
			dev->start_requested = 0;
			dev->audio_mode = 0;
		}
	}

unlock:
	spin_unlock_irqrestore(&dev->lock, flags);
	if (value >= 0) {
		control->complete = cdev->req->complete;
		cdev->req->complete = acc_complete_control;
		cdev->req->zero = 0;
		cdev->req->length = value;
		value = usb_ep_queue(cdev->gadget->ep0, cdev->req, GFP_ATOMIC);
		if (value < 0)
			ERROR(cdev, "setup response queue error\n");
	}

	if (value < 0) {
		cdev->req->context = NULL;
		cdev->req->complete = acc_complete_setup_noop;
		acc_control_put(control);
	}
	if (value == -EOPNOTSUPP)
		DBG(cdev,
		"unknown class-specific ctrl req %02x.%02x v%04x i%04x l%u\n",
			ctrl->bRequestType, ctrl->bRequest,
			wValue, wIndex, wLength);
	put_acc_dev(dev);
	return value;
}

int android_acc_setup_composite(struct usb_composite_dev *cdev,
			      const struct usb_ctrlrequest *ctrl)
{
	u16 w_length = le16_to_cpu(ctrl->wLength);

	if (w_length > USB_COMP_EP0_BUFSIZ) {
		if (ctrl->bRequestType & USB_DIR_IN) {
			/*
			 * Cast away the const, we are going to overwrite on
			 * purpose.
			 */
			__le16 *temp = (__le16 *)&ctrl->wLength;

			*temp = cpu_to_le16(USB_COMP_EP0_BUFSIZ);
			w_length = USB_COMP_EP0_BUFSIZ;
		} else {
			return -EINVAL;
		}
	}
	return __acc_setup(cdev, ctrl);
}

static int acc_setup(struct usb_function *f,
			const struct usb_ctrlrequest *ctrl)
{
	if (f->config != NULL && f->config->cdev != NULL)
		return __acc_setup(f->config->cdev, ctrl);
	else
		return -1;
}

static struct usb_function *acc_alloc(struct usb_function_instance *fi)
{
	struct acc_dev *dev = get_acc_dev();

	dev->function.name = "accessory";
	dev->function.strings = acc_strings;
	dev->function.fs_descriptors = fs_acc_descs;
	dev->function.hs_descriptors = hs_acc_descs;
	dev->function.ss_descriptors = ss_acc_descs;
	dev->function.ssp_descriptors = ssp_acc_descs;
	dev->function.bind = acc_function_bind_configfs;
	dev->function.unbind = acc_function_unbind;
	dev->function.set_alt = acc_function_set_alt;
	dev->function.disable = acc_function_disable;
	dev->function.free_func = acc_free;
	dev->function.req_match = acc_req_match;
	dev->function.setup = acc_setup;

	return &dev->function;
}
DECLARE_USB_FUNCTION_INIT(accessory, acc_alloc_inst, acc_alloc);
MODULE_LICENSE("GPL");
