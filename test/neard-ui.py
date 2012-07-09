#!/usr/bin/env python

import pdb
import sys

import gobject
import gtk

import dbus
import dbus.service
import dbus.mainloop.glib

import traceback

##=================================================================
class Neard:

    #signal handler #1 for Manager
    def manager_Added(self, name):
        print (" Added %s") % name
        self.manager_getDetails()

    #signal handler #2 for Manager
    def manager_Removed(self, name):
        print (" Removed %s") % name
        if self.adapters_remove is not None:
            self.adapter_update(name)
            return

    #connect to the manager in order to be notified on
    #add/remove adapter
    def manager_Connect(self):
        try:
            manager_obj = self.systemBus.get_object('org.neard', "/")
            # Add 2 handlers to follow Adapters
            manager_obj.connect_to_signal('AdapterAdded',
                                           self.manager_Added,
                                          'org.neard.Manager')
            manager_obj.connect_to_signal('AdapterRemoved',
                                          self.manager_Removed,
                                          'org.neard.Manager')
            self.iface_manager = dbus.Interface(manager_obj, 'org.neard.Manager')

        except:
            print ("Can't connect to org.neard.Manager");
            self.iface_manager = None
        #Retrieve the manager informations
        self.manager_getDetails()

    def manager_getDetails(self):
        #No iface_manager means adapter removed
        if self.iface_manager is None:
            if self.adapters_remove is not None:
                self.adapters_remove()
            return
        #Need to update adapter's details
        self.adapter_updateDetails(self.iface_manager.GetProperties())

    def adapter_PropertyChanged(self, prop, value, adapt_path = None):
        print("Prop changed: %s") % prop
        adapt_properties = {}
        adapt_properties[prop] = value
        if prop == "Tags":
            self.tag_updateDetails(adapt_properties)
        else:
            self.adapter_update(adapt_path, adapt_properties)

        #Update the records UI
    def record_updateDetails(self, tag_properties):
         for record_path in tag_properties["Records"]:
            print ("REC %s ") % record_path
            record_obj = self.systemBus.get_object('org.neard',
                                                     record_path)
            record_iface = dbus.Interface(record_obj,'org.neard.Record')
            record_properties = record_iface.GetProperties()

            self.recordregistered[record_path] = True

            # call UI update
            self.records_update(record_path, record_properties)

    #Update the tags UI
    def tag_updateDetails(self, adapt_properties):
        if adapt_properties["Tags"]:
            for tag_path in adapt_properties["Tags"]:
                print ("TAG %s ") % tag_path
                tag_obj = self.systemBus.get_object('org.neard', tag_path)

                tag_iface = dbus.Interface(tag_obj,'org.neard.Tag')
                tag_properties = tag_iface.GetProperties()

                self.tagregistered[tag_path] = True
                # call UI update
                self.tags_update(tag_path, tag_properties)
                #Process the records
                self.record_updateDetails(tag_properties)
        else:
            print ("remove tags and records")
            self.tags_update()
            self.records_update()


    #Something changed, must update the UI
    def adapter_updateDetails(self, properties):
        if self.adapter_update is not None and "Adapters" in properties:
            for adapt_path in properties["Adapters"]:
                if adapt_path in self.adaptregistered:
                    print (" already registered %s") % adapt_path
                else:
                    #Get valuable informations from the object
                    adapter_obj = self.systemBus.get_object('org.neard',
                                                         adapt_path)
                    adapter_obj.connect_to_signal('PropertyChanged',
                                               self.adapter_PropertyChanged,
                                               'org.neard.Adapter',
                                               path_keyword='adapt_path')

                    adapt_iface = dbus.Interface(adapter_obj,'org.neard.Adapter')
                    adapt_properties = adapt_iface.GetProperties()

                    self.adaptregistered[adapt_path] = True

                    #Update display info
                    self.adapter_update(adapt_path, adapt_properties)

                    #udpate UI for tags
                    self.tag_updateDetails(adapt_properties)


    #Search DBUS to find any neard instance
    def neardNameOwnerChanged(self, proxy):
        if proxy:
            print("Neard is connected to System bus")
            self.manager_Connect()
        else:
            print("Neard is disconnected from System bus")
            self.iface_manager = None
            self.adaptregistered = {}
            self.manager_getDetails()

    #Main init function
    def __init__(self, adapter_update = None, adapters_remove = None,
                  tags_update = None, records_update = None):
        self.test = False
        self.adapter_update = adapter_update
        self.adapters_remove = adapters_remove
        self.tags_update = tags_update
        self.records_update = records_update

        self.adaptregistered = {}
        self.tagregistered = {}
        self.recordregistered = {}

        self.systemBus = dbus.SystemBus()

        #Prepare the first handler
        self.systemBus.watch_name_owner('org.neard',
                                         self.neardNameOwnerChanged)

##=================================================================
class NeardUI(Neard):

    # return the current selection
    def adapters_actionToggle(self, i, col):
        if i:
            return self.adapters_list.get_value(i, col)
        return True

    # Action: activate or not the polling mode
    def adapter_pollingToggled(self, poolingRendererToggle, path, user):
        if path:
            i = self.adapters_list.get_iter(path)
            objpath = self.adapters_list.get_value(i, 0)
            adapter_obj = self.systemBus.get_object('org.neard', objpath)
            adapt_iface = dbus.Interface(adapter_obj,'org.neard.Adapter')

            if self.adapters_actionToggle(i, 3):
                print ("Stop Polling %s") % objpath
                adapt_iface.StopPollLoop()
            else:
                print ("Start Polling %s") % objpath
                adapt_iface.StartPollLoop("Initiator")


    #------------------------------
    #Set the field values
    def adapters_setUIList(self, adapt_properties, i, col, name, path = None):
        if name in adapt_properties:
            value = adapt_properties[name]

            if name == "Tags":
                value = "{"
                for tgts in adapt_properties[name]:
                    #For each tag, add it to the tag lbox:
                    #Trim path....
                    short_tgt = tgts[len(path)+1:]

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
            print ("  property %s, value %s") % (name, value)

    # Clear one or all the adapters present in list
    def adapter_RemoveUI(self):
        self.adapters_list.clear()

    #Add, Update or delete a list entry
    def adapter_UpdateUI(self, path = None, adapt_properties = None):
        i = self.adapters_list.get_iter_first()
        while i is not None:
            if self.adapters_list.get_value(i, 0) == path:
                break
            i = self.adapters_list.iter_next(i)

        if adapt_properties is None:
            if i:
                print ("Delete adapter %s") % path
                self.adapters_list.remove(i)
            else:
                print ("Already deleted adapter %s") % path
            return

        if i is None:
            i = self.adapters_list.append()
            self.adapters_list.set_value(i, 0, path)
            print ("Add adapter %s") % (path)
        else:
            print ("Update adapter %s") % (path)


        self.adapters_setUIList(adapt_properties, i, 2, "Powered")
        self.adapters_setUIList(adapt_properties, i, 3, "Polling")
        self.adapters_setUIList(adapt_properties, i, 4, "Protocols")
        self.adapters_setUIList(adapt_properties, i, 5, "Tags", path)

    #--------------------------------------------------
    def tags_setUIList(self, tag_properties, i, col, name):
        if name in tag_properties:
            value = tag_properties[name]

            if name == "Records":
                value = None
                for tags in tag_properties[name]:
                    #For each tag, add it to the tag lbox:
                    if value is None:
                        value = tags
                    else:
                        value = value + "-" + tags

            if name == "Type":
                value = None
                for tags in tag_properties[name]:
                    #For each tag, add it to the tag lbox:
                    if value is None:
                        value = tags
                    else:
                        value = value + "-" + tags

            if value is not None:
                self.tags_list.set_value(i, col, value)
            print ("  property %s, value %s") % (name, value)

    #Add, Update or delete a list entry
    def tag_UpdateUI(self, path = None, tag_properties = None):
        print("Tag Update %s") % path
        i = self.tags_list.get_iter_first()
        while i is not None:
            if self.tags_list.get_value(i, 0) == path:
                break
            i = self.tags_list.iter_next(i)

        #Delete mode: Remove all
        if tag_properties is None:
            i = self.tags_list.get_iter_first()
            while i is not None:
                path_name = self.tags_list.get_value(i, 0)
                print ("Deleted tag %s") % path_name
                self.tags_list.remove(i)
                if self.tags_list.iter_is_valid(i):
                    i = self.tags_list.iter_next(i)
                else:
                    i = None
            return

        if i is None:
            i = self.tags_list.append()
            self.tags_list.set_value(i, 0, path)
            print ("Add tag %s") % (path)
        else:
            print ("Update tag %s") % (path)
        self.tags_setUIList(tag_properties, i, 2, "ReadOnly")
        self.tags_setUIList(tag_properties, i, 3, "Type")
        self.tags_setUIList(tag_properties, i, 4, "Records")

    #--------------------------------------------------
    def records_setUIList(self, record_properties, i, col, name):
        if name in record_properties:
            value = record_properties[name]
        else:
            value = ""
            for rec_data in record_properties:
                if rec_data != "Type":
                     if value != "":
                         value = value + "\n"
                     value = value + rec_data + " :   " +record_properties[rec_data]

        if value is not None:
            self.records_list.set_value(i, col, value)
        print ("  property %s, value %s") % (name, value)

    #Add, Update or delete a list entry
    def record_UpdateUI(self, path = None, record_properties = None):
        print("Record Update %s") % path
        i = self.records_list.get_iter_first()
        while i is not None:
            if self.records_list.get_value(i, 0) == path:
                break
            i = self.records_list.iter_next(i)

         #Delete mode: Remove all records
        if record_properties is None:
            i = self.records_list.get_iter_first()
            while i is not None:
                path_name = self.records_list.get_value(i, 0)
                print ("Delete record %s") % path_name
                self.records_list.remove(i)
                if self.records_list.iter_is_valid(i):
                    i = self.records_list.iter_next(i)
                else:
                    i = None
            return

        if i is None:
            i = self.records_list.append()
            self.records_list.set_value(i, 0, path)
            print ("Add record %s") % (path)
        else:
            print ("Update record %s") % (path)

        self.records_setUIList(record_properties, i, 2, "Type")
        self.records_setUIList(record_properties, i, 3, "Data")


    def tag_RemoveUI(self):
        printf("Tag Remove")

    #Adapter selected on lbox
    def on_adapter_sel_changed(self, selection = None):
        model, iter = selection.get_selected()
        if iter:
             value = self.adapters_list.get_value(iter, 0)
             print ("value %s") % value
             value = self.adapters_list.get_value(iter, 5)
             print ("tag: %s") % value


    #-----------------------------------------------------
    # Prepare TreeView  for Adapters
    def createAdaptersWidgets(self, adaptlist):

        #treeview adapters
        tv_adapters = gtk.TreeView(adaptlist)

        column = gtk.TreeViewColumn("Path", gtk.CellRendererText(), text=0)
        tv_adapters.append_column(column)

        toggle = gtk.CellRendererToggle()
        column = gtk.TreeViewColumn("Powered", toggle, active=2)
        tv_adapters.append_column(column)

        toggle = gtk.CellRendererToggle()
        column = gtk.TreeViewColumn("Polling", toggle, active=3)
        toggle.connect('toggled', self.adapter_pollingToggled, None)
        tv_adapters.append_column(column)

        column = gtk.TreeViewColumn("Protocols",gtk.CellRendererText(), text=4)
        tv_adapters.append_column(column)

        column = gtk.TreeViewColumn("Tags", gtk.CellRendererText(), text=5)
        tv_adapters.append_column(column)

        tv_adapters.get_selection().connect("changed",
                                            self.on_adapter_sel_changed)

        return tv_adapters;

    # Prepare TreeView  for Tags
    def createTagsWidgets(self, tags_list):


        tv_tags = gtk.TreeView(tags_list)

        column = gtk.TreeViewColumn("Path", gtk.CellRendererText(), text=0)
        tv_tags.append_column(column)
        toggle = gtk.CellRendererToggle()
        column = gtk.TreeViewColumn("ReadOnly", toggle, active=2)
        tv_tags.append_column(column)

        column = gtk.TreeViewColumn("Type", gtk.CellRendererText(), text=3)
        tv_tags.append_column(column)

        column = gtk.TreeViewColumn("Record", gtk.CellRendererText(), text=4)
        tv_tags.append_column(column)

        return tv_tags;#

    # Prepare TreeView  for Records
    def createRecordsWidgets(self, records_list):
        #treeview Records
        tv_records = gtk.TreeView(records_list)
        tv_records.connect("row-activated", self.on_record_activated)

        column = gtk.TreeViewColumn("Path", gtk.CellRendererText(), text=0)
        tv_records.append_column(column)

        column = gtk.TreeViewColumn("Type", gtk.CellRendererText(), text=2)
        tv_records.append_column(column)

        column = gtk.TreeViewColumn("Data", gtk.CellRendererText(), text=3)
        tv_records.append_column(column)
        return tv_records;

    def on_record_activated(self, widget, row, col):
        model = widget.get_model()
        recordUI = RecordUI(self.neardDialog, model[row][0], model[row][2])
        recordUI.show()

    def dlg_onResponse(self, dialog, response):
        self.neardDialog.destroy()
        self.neardDialog = None
        if self.response_callback is not None:
            self.response_callback(response)

    #------------------------------
    #Prepare the dialog
    def createDialog(self, title = None):
        if self.title is not None:
            title = self.title
        dialog = gtk.Dialog(title, None,
                            gtk.DIALOG_MODAL |
                            gtk.DIALOG_DESTROY_WITH_PARENT,
                            (gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
        dialog.set_property("resizable", True)
        dialog.set_default_size(800, 300)

        notebook = gtk.Notebook()
        dialog.child.add(notebook)

        # Create the first tab...an adapters's list
        scrolledwindow = gtk.ScrolledWindow()
        widget = self.createAdaptersWidgets(self.adapters_list)
        scrolledwindow.add(widget)
#        notebook.append_page(widget, gtk.Label("Adapters"))
        notebook.append_page(scrolledwindow, gtk.Label("Adapters"))

        scrolledwindow = gtk.ScrolledWindow()
        widget = self.createTagsWidgets(self.tags_list)
        scrolledwindow.add(widget)

        notebook.append_page(scrolledwindow, gtk.Label("Tags"))

        scrolledwindow = gtk.ScrolledWindow()
        widget = self.createRecordsWidgets(self.records_list)
        scrolledwindow.add(widget)
        notebook.append_page(scrolledwindow, gtk.Label("Records"))

        dialog.connect('response', self.dlg_onResponse)
#        dialog.vbox.pack_end(vbox, True, True, 0)
        return dialog

    def show(self):
        if self.neardDialog is None:
            self.neardDialog = self.createDialog()
        self.neardDialog.show_all()

    def __init__(self, title = None, response_callback = None):
        self.title = title
        self.response_callback = response_callback
        self.neardDialog = None

        self.adapters_list = gtk.ListStore(gobject.TYPE_STRING,  # path =0
                                      gobject.TYPE_STRING,  # Name = 1
                                      gobject.TYPE_BOOLEAN, # powered = 2
                                      gobject.TYPE_BOOLEAN, # polling = 3
                                      gobject.TYPE_STRING,  # protocols = 4
                                      gobject.TYPE_STRING)  # tags = 5

        self.tags_list = gtk.ListStore(gobject.TYPE_STRING,  # path =0
                                      gobject.TYPE_STRING,      # Name = 1
                                      gobject.TYPE_BOOLEAN,     # Read Only 2
                                      gobject.TYPE_STRING,      # Type = 3
                                      gobject.TYPE_STRING)     # Record = 4

        self.records_list = gtk.ListStore(gobject.TYPE_STRING,  # path =0
                                      gobject.TYPE_STRING,      # Name = 1
                                      gobject.TYPE_STRING,      # Type = 2
                                      gobject.TYPE_STRING)        # content = 3

        Neard.__init__(self, self.adapter_UpdateUI, self.adapter_RemoveUI
                       , self.tag_UpdateUI, self.record_UpdateUI)

class RecordUI():
    def wr_onResponse(self, dialog, response):
        if response != gtk.RESPONSE_ACCEPT:
            return
        content = self.content_entry.get_text()
        type_name = self.type_combo.get_active_text()
        bus = dbus.SystemBus()
        record_path = self.path
        tag_path = record_path[:record_path.rfind("/")]
        tag = dbus.Interface(bus.get_object("org.neard", tag_path), "org.neard.Tag")
        if type_name in ["Text"]:
            content1 = content.split()
            tag.Write({"Type" : type_name,
                      "Encoding" : content1[0],
                      "Language" : content1[1],
                      "Representation" : ' '.join(content1[2:])})
        else:
            tag.Write({"Type" : type_name,
                       "URI" : content})
        dialog.destroy()

    def __init__(self, parent = None, path = None, type_name = None):
        self.path = path
        type_combo = gtk.combo_box_new_text()
        type_combo.append_text('Text')
        type_combo.append_text('URI')
        type_combo.append_text('SmartPoster')
        if type_name == 'Text':
            type_combo.set_active(0)
        elif type_name == 'URI':
            type_combo.set_active(1)
        elif type_name == 'SmartPoster':
            type_combo.set_active(2)
        fixed = gtk.Fixed()
        content_entry = gtk.Entry()
        fixed.put(type_combo, 20, 40)
        fixed.put(content_entry, 150, 40)
        type_label = gtk.Label("Type")
        content_label = gtk.Label("Content")
        fixed.put(type_label, 20, 15)
        fixed.put(content_label, 150, 15)

        record_dialog = gtk.Dialog("Write Record", parent,
                        gtk.DIALOG_MODAL | gtk.DIALOG_DESTROY_WITH_PARENT,
                        (gtk.STOCK_CANCEL, gtk.RESPONSE_REJECT,gtk.STOCK_OK, gtk.RESPONSE_ACCEPT))
        self.record_dialog = record_dialog
        record_dialog.set_default_size(280, 120)
        record_dialog.set_position(gtk.WIN_POS_CENTER)
        record_dialog.connect('response', self.wr_onResponse)
        hbox = record_dialog.get_content_area()
        hbox.pack_start(fixed)
        self.type_combo = type_combo
        self.content_entry = content_entry
        fixed.show_all()

    def show(self):
        self.record_dialog.run()
        self.record_dialog.destroy()

##=================================================================
if __name__ == "__main__":

    def endmainloop(response):
        mainloop.quit()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    mainloop = gobject.MainLoop()

    m = NeardUI("Neard", endmainloop)
    m.show()

    mainloop.run()
