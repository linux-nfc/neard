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
            manager_obj = self.sessionBus.get_object('org.neard', "/")
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
        if prop == "Targets":
            self.target_updateDetails(adapt_properties)
        else:
            self.adapter_update(adapt_path, adapt_properties)
#

    def adapter_TargetFound(self, adapt_path = None):
        print("Target Found Prop changed: %s") % adapt_path
        self.target_updateDetails(adapt_path)

        #Update the records UI
    def record_updateDetails(self, target_properties):
         for record_path in target_properties["Records"]:
            print ("REC %s ") % record_path
            record_obj = self.sessionBus.get_object('org.neard',
                                                     record_path)
            record_iface = dbus.Interface(record_obj,'org.neard.Record')
            record_properties = record_iface.GetProperties()

            self.recordregistered[record_path] = True

            # call UI update
            self.records_update(record_path, record_properties)

    #Update the targets UI
    def target_updateDetails(self, adapt_properties):
        for target_path in adapt_properties["Targets"]:
            print ("TGT %s ") % target_path
            target_obj = self.sessionBus.get_object('org.neard', target_path)

            target_iface = dbus.Interface(target_obj,'org.neard.Target')
            target_properties = target_iface.GetProperties()

            self.targetregistered[target_path] = True
            # call UI update
            self.targets_update(target_path, target_properties)
            #Process the records
            self.record_updateDetails(target_properties)


    #Something changed, must update the UI
    def adapter_updateDetails(self, properties):
        if self.adapter_update is not None and "Adapters" in properties:
            for adapt_path in properties["Adapters"]:
                if adapt_path in self.adaptregistered:
                    print (" already registered %s") % adapt_path
                else:
                    #Get valuable informations from the object
                    adapter_obj = self.sessionBus.get_object('org.neard',
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

                    #udpate UI for targets
                    self.target_updateDetails(adapt_properties)


    #Search DBUS to find any neard instance
    def neardNameOwnerChanged(self, proxy):
        if proxy:
            print("Neard is connected to session bus")
            self.manager_Connect()
        else:
            print("Neard is disconnected from session bus")
            self.iface_manager = None
            self.adaptregistered = {}
            self.manager_getDetails()

    #Main init function
    def __init__(self, adapter_update = None, adapters_remove = None,
                  targets_update = None, records_update = None):
        self.test = False
        self.adapter_update = adapter_update
        self.adapters_remove = adapters_remove
        self.targets_update = targets_update
        self.records_update = records_update

        self.adaptregistered = {}
        self.targetregistered = {}
        self.recordregistered = {}

        self.sessionBus = dbus.SessionBus()

        #Prepare the first handler
        self.sessionBus.watch_name_owner('org.neard',
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
            adapter_obj = self.sessionBus.get_object('org.neard', objpath)
            adapt_iface = dbus.Interface(adapter_obj,'org.neard.Adapter')

            if self.adapters_actionToggle(i, 3):
                print ("Stop Polling %s") % objpath
                adapt_iface.StopPoll()
            else:
                print ("Start Polling %s") % objpath
                adapt_iface.StartPoll()


    #------------------------------
    #Set the field values
    def adapters_setUIList(self, adapt_properties, i, col, name, path = None):
        if name in adapt_properties:
            value = adapt_properties[name]

            if name == "Targets":
                value = "{"
                for tgts in adapt_properties[name]:
                    #For each target, add it to the target lbox:
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
                        value = value + "-" + protos

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
##                self.target_UpdateUI(path)

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
        self.adapters_setUIList(adapt_properties, i, 5, "Targets", path)

    #--------------------------------------------------
    def targets_setUIList(self, target_properties, i, col, name):
        if name in target_properties:
            value = target_properties[name]

            if name == "Records":
                value = None
                for tgts in target_properties[name]:
                    #For each target, add it to the target lbox:
                    if value is None:
                        value = tgts
                    else:
                        value = value + "-" + tgts

            if name == "TagType":
                value = None
                for tgts in target_properties[name]:
                    #For each target, add it to the target lbox:
                    if value is None:
                        value = tgts
                    else:
                        value = value + "-" + tgts

            if value is not None:
                self.targets_list.set_value(i, col, value)
            print ("  property %s, value %s") % (name, value)

    #Add, Update or delete a list entry
    def target_UpdateUI(self, path = None, target_properties = None):
        print("Target Update %s") % path
        i = self.targets_list.get_iter_first()
        while i is not None:
            if self.targets_list.get_value(i, 0) == path:
                break
            i = self.targets_list.iter_next(i)

        #Delete mode:
        if target_properties is None:
            i = self.targets_list.get_iter_first()
            while i is not None:
                path_name = self.targets_list.get_value(i, 0)

                if path == path_name[:len(path)-1]:
                    print ("Delete target %s") % path_name
                    self.targets_list.remove(i)
                else:
                    print ("Already deleted target %s") % path_name
                i = self.targets_list.iter_next(i)
            return

        if i is None:
            i = self.targets_list.append()
            self.targets_list.set_value(i, 0, path)
            print ("Add target %s") % (path)
        else:
            print ("Update target %s") % (path)
        self.targets_setUIList(target_properties, i, 2, "ReadOnly")
        self.targets_setUIList(target_properties, i, 3, "Type")
        self.targets_setUIList(target_properties, i, 4, "TagType")
        self.targets_setUIList(target_properties, i, 5, "Records")

    #--------------------------------------------------
    def records_setUIList(self, record_properties, i, col, name):
        if name in record_properties:
            value = record_properties[name]
        else:
            value = "{"
            for rec_data in record_properties:
                if rec_data != "Type":
                     if value != "{":
                         value = value + "-"
                     value = value + rec_data + ":" +record_properties[rec_data]
            value = value + "}"

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

        if record_properties is None:
            if i:
                print ("Delete record %s") % path
                self.records_list.remove(i)
            else:
                print ("Already deleted record %s") % path
            return

        if i is None:
            i = self.records_list.append()
            self.records_list.set_value(i, 0, path)
            print ("Add record %s") % (path)
        else:
            print ("Update record %s") % (path)

        self.records_setUIList(record_properties, i, 2, "Type")
        self.records_setUIList(record_properties, i, 3, "Data")


    def target_RemoveUI(self):
        printf("Target Remove")

    #Adapter selected on lbox
    def on_adapter_sel_changed(self, selection = None):
        model, iter = selection.get_selected()
        if iter:
             value = self.adapters_list.get_value(iter, 0)
             print ("value %s") % value
             value = self.adapters_list.get_value(iter, 5)
             print ("target: %s") % value


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

        column = gtk.TreeViewColumn("Targets", gtk.CellRendererText(), text=5)
        tv_adapters.append_column(column)

        tv_adapters.get_selection().connect("changed",
                                            self.on_adapter_sel_changed)

        return tv_adapters;

    # Prepare TreeView  for Targets
    def createTargetsWidgets(self, targets_list):


        tv_targets = gtk.TreeView(targets_list)

        column = gtk.TreeViewColumn("Path", gtk.CellRendererText(), text=0)
        tv_targets.append_column(column)
        toggle = gtk.CellRendererToggle()
        column = gtk.TreeViewColumn("ReadOnly", toggle, active=2)
        tv_targets.append_column(column)

        column = gtk.TreeViewColumn("Type", gtk.CellRendererText(), text=3)
        tv_targets.append_column(column)

        column = gtk.TreeViewColumn("NFC Type ", gtk.CellRendererText(), text=4)
        tv_targets.append_column(column)

        column = gtk.TreeViewColumn("Record", gtk.CellRendererText(), text=5)
        tv_targets.append_column(column)

        return tv_targets;#

    # Prepare TreeView  for Records
    def createRecordsWidgets(self, records_list):
        #treeview Records
        tv_records = gtk.TreeView(records_list)

        column = gtk.TreeViewColumn("Path", gtk.CellRendererText(), text=0)
        tv_records.append_column(column)

        column = gtk.TreeViewColumn("Type", gtk.CellRendererText(), text=2)
        tv_records.append_column(column)

        column = gtk.TreeViewColumn("Data", gtk.CellRendererText(), text=3)
        tv_records.append_column(column)
        return tv_records;

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
        widget = self.createTargetsWidgets(self.targets_list)
        scrolledwindow.add(widget)
        #notebook.append_page(widget, gtk.Label("Targets"))
        notebook.append_page(scrolledwindow, gtk.Label("Targets"))

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
                                      gobject.TYPE_STRING)  # targets = 5

        self.targets_list = gtk.ListStore(gobject.TYPE_STRING,  # path =0
                                      gobject.TYPE_STRING,      # Name = 1
                                      gobject.TYPE_BOOLEAN,     # Read Only 2
                                      gobject.TYPE_STRING,      # tag Type = 3
                                      gobject.TYPE_STRING,      # Type = 4
                                      gobject.TYPE_STRING)     # Record = 5

        self.records_list = gtk.ListStore(gobject.TYPE_STRING,  # path =0
                                      gobject.TYPE_STRING,      # Name = 1
                                      gobject.TYPE_STRING,      # Type = 2
                                      gobject.TYPE_STRING)        # content = 3

        Neard.__init__(self, self.adapter_UpdateUI, self.adapter_RemoveUI
                       , self.target_UpdateUI, self.record_UpdateUI)

##=================================================================
if __name__ == "__main__":

    def endmainloop(response):
        mainloop.quit()

    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    mainloop = gobject.MainLoop()

    m = NeardUI("Neard", endmainloop)
    m.show()

    mainloop.run()
