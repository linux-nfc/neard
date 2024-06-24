#!/usr/bin/env python3

import neardutils
import traceback
import dbus.mainloop.glib
import dbus.service
import dbus
import pdb
import sys

import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk
from gi.repository import GLib
from gi.repository import GObject


# =================================================================


class Neard:

    def interface_Added(self, path, interface):
        print(" New interface added: %s" % path)
        self.objects = neardutils.get_managed_objects()
        self.interface_updateDetails(interface, path)

    def interface_Removed(self, path, interface):
        print(" Remove interface: %s" % path)
        self.objects = neardutils.get_managed_objects()
        self.interface_updateDetails(interface)

    # connect to the object_manager in order to be notified on
    # add/remove interface

    def interfaces_Connect(self):
        try:
            print('interfaces_Connect')
            bus = dbus.SystemBus()
            self.objects = neardutils.get_managed_objects()
            bus.add_signal_receiver(self.interface_Added, bus_name=neardutils.SERVICE_NAME,
                                    dbus_interface="org.freedesktop.DBus.ObjectManager",
                                    signal_name="InterfacesAdded")
            bus.add_signal_receiver(self.interface_Removed, bus_name=neardutils.SERVICE_NAME,
                                    dbus_interface="org.freedesktop.DBus.ObjectManager",
                                    signal_name="InterfacesRemoved")
        except BaseException:
            print("Can't connect to org.freedesktop.DBus.ObjectManager")
            self.objects = None

        # Retrieve the manager informations
        self.interface_getDetails()

    def interface_getDetails(self):
        self.adapter_updateDetails()

    def interface_updateDetails(self, interface, path=None):
        if neardutils.ADAPTER_INTERFACE in interface:
            self.adapter_updateDetails()
        elif neardutils.TAG_INTERFACE in interface:
            self.tag_updateDetails(path)
        elif neardutils.RECORD_INTERFACE in interface:
            self.record_updateDetails(path)

    def adapter_PropertyChanged(self, prop, value, adapt_path=None):
        print("Prop changed: %s" % prop)
        adapt_properties = {}
        adapt_properties[prop] = value
        if prop == "Tags":
            self.tag_updateDetails(adapt_properties)
        else:
            self.adapter_update(adapt_path, adapt_properties)

    # Update the records UI
    def record_updateDetails(self, tag_path=None):
        if tag_path is not None:
            for record_path, record_iface in self.objects.items():

                if neardutils.RECORD_INTERFACE not in record_iface:
                    continue

                record_properties = record_iface[neardutils.RECORD_INTERFACE]

                self.recordregistered[record_path] = True

                # call UI update
                self.records_update(record_path, record_properties)
        else:
            self.records_update()

    # Update the tags UI
    def tag_updateDetails(self, adapter_path=None):
        if adapter_path is not None:
            for tag_path, interfaces in self.objects.items():
                if neardutils.TAG_INTERFACE not in interfaces:
                    continue

                print("TAG %s " % tag_path)

                tag_properties = interfaces[neardutils.TAG_INTERFACE]

                self.tagregistered[tag_path] = True
                # call UI update
                self.tags_update(tag_path, tag_properties)
                # Process the records
                self.record_updateDetails(tag_properties)
        else:
            print("remove tags and records")
            self.tags_update()
            self.records_update()

    # Something changed, must update the UI

    def adapter_updateDetails(self):
        for adapt_path, interfaces in self.objects.items():
            if neardutils.ADAPTER_INTERFACE not in interfaces:
                continue

            if adapt_path in self.adaptregistered:
                print(" already registered %s" % adapt_path)
            else:
                adapt_properties = interfaces[neardutils.ADAPTER_INTERFACE]

                self.adaptregistered[adapt_path] = True

                # Update display info
                self.adapter_update(adapt_path, adapt_properties)

                # udpate UI for tags
                self.tag_updateDetails()

    # Search DBUS to find any neard instance

    def neardNameOwnerChanged(self, proxy):
        if proxy:
            print("Neard is connected to System bus")
            self.interfaces_Connect()
        else:
            print("Neard is disconnected from System bus")
            self.iface_manager = None
            self.adaptregistered = {}
            self.interface_getDetails()

    # Main init function
    def __init__(self, adapter_update=None, adapters_remove=None,
                 tags_update=None, records_update=None):
        self.test = False
        self.adapter_update = adapter_update
        self.adapters_remove = adapters_remove
        self.tags_update = tags_update
        self.records_update = records_update

        self.adaptregistered = {}
        self.tagregistered = {}
        self.recordregistered = {}

        self.systemBus = dbus.SystemBus()

        # Prepare the first handler
        self.systemBus.watch_name_owner(neardutils.SERVICE_NAME,
                                        self.neardNameOwnerChanged)

# =================================================================


class NeardUI(Neard):

    # return the current selection
    def adapters_actionToggle(self, i, col):
        if i:
            return self.adapters_list.get_value(i, col)
        return True

    # Action: activate or not the adapter
    def adapter_poweredToggled(self, poweredRendererToggle, path, user):
        bus = dbus.SystemBus()

        if path:
            i = self.adapters_list.get_iter(path)
            objpath = self.adapters_list.get_value(i, 0)
            adapt_iface = neardutils.find_adapter(path)
            adapter = dbus.Interface(bus.get_object(neardutils.SERVICE_NAME, adapt_iface.object_path),
                                     "org.freedesktop.DBus.Properties")

            try:
                if self.adapters_actionToggle(i, 2):
                    print("Disable Adapter %s" % objpath)
                    adapter.Set(neardutils.ADAPTER_INTERFACE, "Powered", False)
                    self.adapters_list.set_value(i, 2, 0)
                else:
                    print("Enable Adapter %s" % objpath)
                    adapter.Set(neardutils.ADAPTER_INTERFACE, "Powered", True)
                    self.adapters_list.set_value(i, 2, 1)

            except BaseException:
                print("Can't toggle adapter %s" % objpath)

    # Action: activate or not the polling mode
    def adapter_pollingToggled(self, poolingRendererToggle, path, user):
        if path:
            i = self.adapters_list.get_iter(path)
            objpath = self.adapters_list.get_value(i, 0)
            adapt_iface = neardutils.find_adapter(path)

            try:
                if self.adapters_actionToggle(i, 3):
                    print("Stop Polling %s" % objpath)
                    adapt_iface.StopPollLoop()
                    self.adapters_list.set_value(i, 3, 0)
                else:
                    print("Start Polling %s" % objpath)
                    adapt_iface.StartPollLoop("Initiator")
                    self.adapters_list.set_value(i, 3, 1)
            except BaseException:
                print("Can't toggle polling on adapter %s" % objpath)

    # ------------------------------
    # Set the field values
    def adapters_setUIList(self, adapt_properties, i, col, name, path=None):
        if name in adapt_properties:
            value = adapt_properties[name]

            if name == "Tags":
                value = "{"
                for tgts in adapt_properties[name]:
                    # For each tag, add it to the tag lbox:
                    # Trim path....
                    short_tgt = tgts[len(path) + 1:]

                    if value == "{":
                        value = "{" + short_tgt
                    else:
                        value = value + "," + short_tgt
                value = value + "}"

            if name == "Protocols":
                value = None
                for protos in adapt_properties[name]:
                    if value is None:
                        value = protos
                    else:
                        value = value + " " + protos

            if value is not None:
                self.adapters_list.set_value(i, col, value)
            print("  property %s, value %s" % (name, value))

    # Clear one or all the adapters present in list
    def adapter_RemoveUI(self):
        self.adapters_list.clear()

    # Add, Update or delete a list entry
    def adapter_UpdateUI(self, path=None, adapt_properties=None):
        i = self.adapters_list.get_iter_first()
        while i is not None:
            if self.adapters_list.get_value(i, 0) == path:
                break
            i = self.adapters_list.iter_next(i)

        if adapt_properties is None:
            if i:
                print("Delete adapter %s" % path)
                self.adapters_list.remove(i)
            else:
                print("Already deleted adapter %s" % path)
            return

        if i is None:
            i = self.adapters_list.append()
            self.adapters_list.set_value(i, 0, path)
            print("Add adapter %s" % path)
        else:
            print("Update adapter %s" % path)

        self.adapters_setUIList(adapt_properties, i, 2, "Powered")
        self.adapters_setUIList(adapt_properties, i, 3, "Polling")
        self.adapters_setUIList(adapt_properties, i, 4, "Protocols")
        self.adapters_setUIList(adapt_properties, i, 5, "Tags", path)

    # --------------------------------------------------
    def tags_setUIList(self, tag_properties, i, col, name):
        if name in tag_properties:
            value = tag_properties[name]

            if name == "Type":
                value = None
                for tags in tag_properties[name]:
                    # For each tag, add it to the tag lbox:
                    if value is None:
                        value = tags
                    else:
                        value += tags

            if value is not None:
                self.tags_list.set_value(i, col, value)
            print("  property %s, value %s" % (name, value))

    # Add, Update or delete a list entry
    def tag_UpdateUI(self, path=None, tag_properties=None):
        print("Tag Update %s" % path)
        i = self.tags_list.get_iter_first()
        while i is not None:
            if self.tags_list.get_value(i, 0) == path:
                break
            i = self.tags_list.iter_next(i)

        # Delete mode: Remove all
        if tag_properties is None:
            i = self.tags_list.get_iter_first()
            while i is not None:
                path_name = self.tags_list.get_value(i, 0)
                print("Deleted tag %s" % path_name)
                self.tags_list.remove(i)
                if self.tags_list.iter_is_valid(i):
                    i = self.tags_list.iter_next(i)
                else:
                    i = None
            return

        if i is None:
            i = self.tags_list.append()
            self.tags_list.set_value(i, 0, path)
            print("Add tag %s" % path)
        else:
            print("Update tag %s" % path)
        self.tags_setUIList(tag_properties, i, 2, "ReadOnly")
        self.tags_setUIList(tag_properties, i, 3, "Type")

    # --------------------------------------------------
    def records_setUIList(self, record_properties, i, col, name):
        if name in record_properties:
            value = record_properties[name]
        else:
            value = ""
            for rec_data in record_properties:
                if rec_data != "Type":
                    if value != "":
                        value = value + "\n"
                    value = value + rec_data + " :   " + \
                        record_properties[rec_data]

        if value is not None:
            self.records_list.set_value(i, col, value)
        print("  property %s, value %s" % (name, value))

    # Add, Update or delete a list entry
    def record_UpdateUI(self, path=None, record_properties=None):
        print("Record Update %s" % path)
        i = self.records_list.get_iter_first()
        while i is not None:
            if self.records_list.get_value(i, 0) == path:
                break
            i = self.records_list.iter_next(i)

         # Delete mode: Remove all records
        if record_properties is None:
            i = self.records_list.get_iter_first()
            while i is not None:
                path_name = self.records_list.get_value(i, 0)
                print("Delete record %s" % path_name)
                self.records_list.remove(i)
                if self.records_list.iter_is_valid(i):
                    i = self.records_list.iter_next(i)
                else:
                    i = None
            return

        if i is None:
            i = self.records_list.append()
            self.records_list.set_value(i, 0, path)
            print("Add record %s" % path)
        else:
            print("Update record %s" % path)

        self.records_setUIList(record_properties, i, 2, "Type")
        self.records_setUIList(record_properties, i, 3, "Data")

    def tag_RemoveUI(self):
        printf("Tag Remove")

    # Adapter selected on lbox
    def on_adapter_sel_changed(self, selection=None):
        model, iter = selection.get_selected()
        if iter:
            value = self.adapters_list.get_value(iter, 0)
            print("value %s" % value)
            value = self.adapters_list.get_value(iter, 5)
            print("tag: %s" % value)

    # -----------------------------------------------------
    # Prepare TreeView  for Adapters

    def createAdaptersWidgets(self, adaptlist):

        # treeview adapters
        tv_adapters = Gtk.TreeView(model=adaptlist)

        column = Gtk.TreeViewColumn("Path", Gtk.CellRendererText(), text=0)
        tv_adapters.append_column(column)

        toggle = Gtk.CellRendererToggle()
        column = Gtk.TreeViewColumn("Powered", toggle, active=2)
        toggle.connect("toggled", self.adapter_poweredToggled, None)
        tv_adapters.append_column(column)

        toggle = Gtk.CellRendererToggle()
        column = Gtk.TreeViewColumn("Polling", toggle, active=3)
        toggle.connect("toggled", self.adapter_pollingToggled, None)
        tv_adapters.append_column(column)

        column = Gtk.TreeViewColumn(
            "Protocols", Gtk.CellRendererText(), text=4)
        tv_adapters.append_column(column)

        tv_adapters.get_selection().connect("changed",
                                            self.on_adapter_sel_changed)

        return tv_adapters

    # Prepare TreeView  for Tags
    def createTagsWidgets(self, tags_list):

        tv_tags = Gtk.TreeView(model=tags_list)

        column = Gtk.TreeViewColumn("Path", Gtk.CellRendererText(), text=0)
        tv_tags.append_column(column)
        toggle = Gtk.CellRendererToggle()
        column = Gtk.TreeViewColumn("ReadOnly", toggle, active=2)
        tv_tags.append_column(column)

        column = Gtk.TreeViewColumn("Type", Gtk.CellRendererText(), text=3)
        tv_tags.append_column(column)

        return tv_tags
        #

    # Prepare TreeView  for Records
    def createRecordsWidgets(self, records_list):
        # treeview Records
        tv_records = Gtk.TreeView(model=records_list)
        tv_records.connect("row-activated", self.on_record_activated)

        column = Gtk.TreeViewColumn("Path", Gtk.CellRendererText(), text=0)
        tv_records.append_column(column)

        column = Gtk.TreeViewColumn("Type", Gtk.CellRendererText(), text=2)
        tv_records.append_column(column)

        column = Gtk.TreeViewColumn("Data", Gtk.CellRendererText(), text=3)
        tv_records.append_column(column)
        return tv_records

    # Prepare TreeView  for Records
    def createWriteWidgets(self, records_list):
        # treeview Records
        tv_records = Gtk.TreeView(model=records_list)
        # tv_records.connect("row-activated", self.on_record_activated)

        # column = Gtk.TreeViewColumn("Path", Gtk.CellRendererText(), text=0)
        # tv_records.append_column(column)

        # column = Gtk.TreeViewColumn("Type", Gtk.CellRendererText(), text=2)
        # tv_records.append_column(column)

        # column = Gtk.TreeViewColumn("Data", Gtk.CellRendererText(), text=3)
        # tv_records.append_column(column)
        return tv_records

    def on_record_activated(self, widget, row, col):
        model = widget.get_model()
        recordUI = RecordUI(self.neardDialog, model[row][0], model[row][2])
        recordUI.show()

    def dlg_onResponse(self, dialog, response):
        self.neardDialog.destroy()
        self.neardDialog = None
        if self.response_callback is not None:
            self.response_callback(response)

    # ------------------------------
    # Prepare the dialog
    def createDialog(self, title=None):
        if self.title is not None:
            title = self.title
        dialog = Gtk.Dialog(title, None, modal=True, destroy_with_parent=True)
        dialog.add_button("_OK", Gtk.ResponseType.ACCEPT)
        dialog.set_property("resizable", True)
        dialog.set_default_size(800, 300)

        notebook = Gtk.Notebook()
        dialog.get_content_area().add(notebook)
        notebook.set_vexpand(True)

        # Create the first tab...an adapters's list
        scrolledwindow = Gtk.ScrolledWindow()
        widget = self.createAdaptersWidgets(self.adapters_list)
        scrolledwindow.add(widget)
        notebook.append_page(scrolledwindow, Gtk.Label(label="Adapters"))

        scrolledwindow = Gtk.ScrolledWindow()
        widget = self.createTagsWidgets(self.tags_list)
        scrolledwindow.add(widget)

        notebook.append_page(scrolledwindow, Gtk.Label(label="Tags"))

        scrolledwindow = Gtk.ScrolledWindow()
        widget = self.createRecordsWidgets(self.records_list)
        scrolledwindow.add(widget)
        notebook.append_page(scrolledwindow, Gtk.Label(label="Records"))

        dialog.connect('response', self.dlg_onResponse)
        return dialog

    def show(self):
        if self.neardDialog is None:
            self.neardDialog = self.createDialog()
        self.neardDialog.show_all()

    def __init__(self, title=None, response_callback=None):
        self.title = title
        self.response_callback = response_callback
        self.neardDialog = None

        self.adapters_list = Gtk.ListStore(
            GObject.TYPE_STRING,  # path =0
            GObject.TYPE_STRING,  # Name = 1
            GObject.TYPE_BOOLEAN,  # powered = 2
            GObject.TYPE_BOOLEAN,  # polling = 3
            GObject.TYPE_STRING,  # protocols = 4
            GObject.TYPE_STRING  # tags = 5
        )

        self.tags_list = Gtk.ListStore(
            GObject.TYPE_STRING,  # path =0
            GObject.TYPE_STRING,  # Name = 1
            GObject.TYPE_BOOLEAN,  # Read Only 2
            GObject.TYPE_STRING,  # Type = 3
            GObject.TYPE_STRING  # Record = 4
        )

        self.records_list = Gtk.ListStore(
            GObject.TYPE_STRING,  # path =0
            GObject.TYPE_STRING,  # Name = 1
            GObject.TYPE_STRING,  # Type = 2
            GObject.TYPE_STRING  # content = 3
        )

        Neard.__init__(
            self,
            self.adapter_UpdateUI,
            self.adapter_RemoveUI,
            self.tag_UpdateUI,
            self.record_UpdateUI)


class RecordUI():
    def wr_onResponse(self, dialog, response):
        if response != Gtk.RESPONSE_ACCEPT:
            return
        content = self.content_entry.get_text()
        type_name = self.type_combo.get_active_text()
        bus = dbus.SystemBus()
        record_path = self.path
        tag_path = record_path[:record_path.rfind("/")]
        tag = dbus.Interface(
            bus.get_object(
                neardutils.SERVICE_NAME,
                tag_path),
            neardutils.TAG_INTERFACE)
        if type_name in ["Text"]:
            content1 = content.split()
            tag.Write({"Type": type_name,
                       "Encoding": content1[0],
                       "Language": content1[1],
                       "Representation": ' '.join(content1[2:])})
        else:
            tag.Write({"Type": type_name,
                       "URI": content})
        dialog.destroy()

    def __init__(self, parent=None, path=None, type_name=None):
        self.path = path
        type_combo = Gtk.combo_box_new_text()
        type_combo.append_text("Text")
        type_combo.append_text("URI")
        type_combo.append_text("SmartPoster")
        if type_name == "Text":
            type_combo.set_active(0)
        elif type_name == 'URI':
            type_combo.set_active(1)
        elif type_name == 'SmartPoster':
            type_combo.set_active(2)
        fixed = Gtk.Fixed()
        content_entry = Gtk.Entry()
        fixed.put(type_combo, 20, 40)
        fixed.put(content_entry, 150, 40)
        type_label = Gtk.Label("Type")
        content_label = Gtk.Label("Content")
        fixed.put(type_label, 20, 15)
        fixed.put(content_label, 150, 15)

        record_dialog = Gtk.Dialog(
            "Write Record",
            parent,
            modal=True,
            destroy_with_parent=True
        )
        record_dialog.add_button("_Cancel", Gtk.RESPONSE_REJECT)
        record_dialog.add_button("_OK", Gtk.RESPONSE_ACCEPT)
        self.record_dialog = record_dialog
        record_dialog.set_default_size(280, 120)
        record_dialog.set_position(Gtk.WindowPosition.CENTER)
        record_dialog.connect('response', self.wr_onResponse)
        hbox = record_dialog.get_content_area()
        hbox.pack_start(fixed)
        self.type_combo = type_combo
        self.content_entry = content_entry
        fixed.show_all()

    def show(self):
        self.record_dialog.run()
        self.record_dialog.destroy()


# =================================================================
if __name__ == "__main__":

    def endmainloop(response):
        mainloop.quit()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    mainloop = GLib.MainLoop()

    m = NeardUI("Neard", endmainloop)
    m.show()

    mainloop.run()
