import dbus

SERVICE_NAME = "org.neard"
ADAPTER_INTERFACE = SERVICE_NAME + ".Adapter"
DEVICE_INTERFACE = SERVICE_NAME + ".Device"
TAG_INTERFACE = SERVICE_NAME + ".Tag"
RECORD_INTERFACE = SERVICE_NAME + ".Record"

def get_managed_objects():
	bus = dbus.SystemBus()
	manager = dbus.Interface(bus.get_object("org.neard", "/"),
				"org.freedesktop.DBus.ObjectManager")
	return manager.GetManagedObjects()

def find_adapter(pattern=None):
	return find_adapter_in_objects(get_managed_objects(), pattern)

def find_adapter_in_objects(objects, pattern=None):
	bus = dbus.SystemBus()
	for path, ifaces in objects.iteritems():
		adapter = ifaces.get(ADAPTER_INTERFACE)
		if adapter is None:
			continue
		if not pattern or path.endswith(pattern):
			obj = bus.get_object(SERVICE_NAME, path)
			return dbus.Interface(obj, ADAPTER_INTERFACE)
	raise Exception("NFC adapter not found")

def find_device(pattern=None):
	return find_device_in_objects(get_managed_objects(), pattern)

def find_device_in_objects(objects, pattern=None):
	bus = dbus.SystemBus()
	for path, ifaces in objects.iteritems():
		device = ifaces.get(DEVICE_INTERFACE)
		if device is None:
			continue
		if not pattern or path.endswith(pattern):
			obj = bus.get_object(SERVICE_NAME, path)
			return dbus.Interface(obj, DEVICE_INTERFACE)
	raise Exception("NFC device not found")

def find_tag(pattern=None):
	return find_tag_in_objects(get_managed_objects(), pattern)

def find_tag_in_objects(objects, pattern=None):
	bus = dbus.SystemBus()
	for path, ifaces in objects.iteritems():
		tag = ifaces.get(TAG_INTERFACE)
		if tag is None:
			continue
		if not pattern or path.endswith(pattern):
			obj = bus.get_object(SERVICE_NAME, path)
			return dbus.Interface(obj, TAG_INTERFACE)
	raise Exception("NFC tag not found")

def find_record(pattern=None):
	return find_record_in_objects(get_managed_objects(), pattern)

def find_record_in_objects(objects, pattern=None):
	bus = dbus.SystemBus()
	for path, ifaces in objects.iteritems():
		record = ifaces.get(RECORD_INTERFACE)
		if record is None:
			continue
		if not pattern or path.endswith(pattern):
			obj = bus.get_object(SERVICE_NAME, path)
			return dbus.Interface(obj, RECORD_INTERFACE)
	raise Exception("NFC record not found")

def dump_record(record_path):
	bus = dbus.SystemBus()
	record_prop = dbus.Interface(bus.get_object("org.neard", record_path),
					"org.freedesktop.DBus.Properties")

	properties = record_prop.GetAll(RECORD_INTERFACE)

	for key in properties.keys():
		if key in ["Representation"]:
			val = unicode(properties[key])
		else:
			val = str(properties[key])
		print "      %s = %s" % (key, val)

def dump_all_records(path):
	bus = dbus.SystemBus()
	om = dbus.Interface(bus.get_object("org.neard", "/"),
					"org.freedesktop.DBus.ObjectManager")
	objects = om.GetManagedObjects()
	for path, interfaces in objects.iteritems():
		if "org.neard.Record" not in interfaces:
			continue

		if path.startswith(path):
			print("  [ %s ]" % (path))
			dump_record(path)
