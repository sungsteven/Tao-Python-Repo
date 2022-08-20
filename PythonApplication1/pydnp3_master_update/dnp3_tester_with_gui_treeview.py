from time import sleep
from datetime import datetime
from tkinter.ttk import Labelframe
import serial
import binascii
import queue
import threading
import tkinter as tk
from tkinter import ttk
import serial.tools.list_ports
from DNP3_SC.dnp3master import *
# from DNP3_SC.dnp3_frame import *
# from DNP3_SC.utils import *


__author__ = "Tao Sun"

solicitedMsgRec = False
def solicitedMsgReady(oper_mode=Operation_Mode.Get, new_val=False):
    global solicitedMsgRec
    if oper_mode == Operation_Mode.Initialize:
        solicitedMsgRec = False
    elif oper_mode == Operation_Mode.Set:
        solicitedMsgRec = new_val
    return solicitedMsgRec

unsolicitedMsgBuffer = []
def unsolicitedMsg(oper_mode=Operation_Mode.Get, new_val=[]):
    global unsolicitedMsgBuffer
    if oper_mode == Operation_Mode.Initialize:
        unsolicitedMsgBuffer = []
    elif oper_mode == Operation_Mode.Set:
        unsolicitedMsgBuffer = new_val
    return unsolicitedMsgBuffer

def read_from_socket(socket_conn, address, unsolicit_queue, stopToThreadQueue, stopFromThreadQueue):
    rtu_num = address[0]
    while True:
        sequence_Bytes = []
        for _ in range(5):                  # assuming there are up to five segments for each sequence
            byte_data = socket_conn.get()     # Keep receiving data
            if byte_data != b'':
                sequence_Bytes.append(byte_data)
                # Check if this received fragment is the last one of this sequence
                if len(byte_data) > 10:
                    finBitVal = f'{byte_data[10]:08b}'[::-1][7]
                    if finBitVal == '1':          # this is the final fragment, stop reading
                        break
                else:
                    break
            else:
                break
        if len(sequence_Bytes) >0:
            cat_seqBytes = ReceivedFrame.categorize_receivedBytes(sequence_Bytes)
            header_str = 'Solicited' if not cat_seqBytes['Unsolicited Response'] else 'Unsolicited'
            for index in range(len(sequence_Bytes)):
                seq_num_str = f", seq#{cat_seqBytes['Sequence Number']}" if cat_seqBytes['Sequence Number'] not in [253, 254] else ''
                if len(sequence_Bytes) >1:
                    print(f'{header_str} response {index+1} of {len(sequence_Bytes)} from outstation: {binascii.hexlify(sequence_Bytes[index])}')
                    table_title = f" [{datetime.now().strftime('%m/%d/%Y %I:%M:%S.%f')[:-3]}] {header_str} response ({index+1} of {len(sequence_Bytes)}) from RTU[{rtu_num}]{seq_num_str}"
                else:
                    print(f'{header_str} response from outstation: {binascii.hexlify(sequence_Bytes[index])}')
                    table_title = f" [{datetime.now().strftime('%m/%d/%Y %I:%M:%S.%f')[:-3]}] {header_str} response from RTU[{rtu_num}]{seq_num_str}"
                if cat_seqBytes['Unsolicited Response']:
                    if unsolicit_queue.qsize() == 1000:     # make sure the buffer is not overflowed (>1000 elements)
                        unsolicit_queue.get()
                    unsolicit_queue.put(sequence_Bytes[index])
                readoutFrame = ReceivedFrame.convert2frame(sequence_Bytes[index], index==0)
                add_items_to_treeview(readoutFrame.__dict__, table_title)               
                print('Done with this sequence reading!')


            if cat_seqBytes['Confirmation Required']:                   # if confirmatio is required from the outstation
                op_params = {'Function Codes': Function_Code.CONFIRM, 'Object Info': []}
                table, table_title = socket_conn.send(address, applCtrlVal=cat_seqBytes['Application Ctrl'] & 0xDF, datalinkCtrlVal=0xC4, objDefVal=op_params, notPrint=cat_seqBytes['Unsolicited Response'])
                if table_title:
                    add_items_to_treeview(table, table_title)
            else:                                                       # if confirmation is not required
                if cat_seqBytes['Sequence Number'] == 253:              # This is response but not confirmation sending from master to outstation.
                                                                        # Frames should have PRM=1 and DIR=1
                    op_params = {'Function Codes': Function_Code.READ, 'Object Info': []}
                    table, table_title = socket_conn.send(address, applCtrlVal=0xC0, datalinkCtrlVal=TransmitFrame.getDataLinkReqCtrl(cat_seqBytes['Function Code']), objDefVal=op_params)
                    if table_title:
                        add_items_to_treeview(table, table_title)
        else:
            #print('There is no response from the outstation. Try a different request.')
            pass
        if not stopToThreadQueue.empty():
            stopToThreadQueue.get()
            stopFromThreadQueue.put(False)
            break

start_time = datetime.now()
def check_link_status(socket_conn, address, stopToThreadQueue, stopFromThreadQueue):
    global start_time
    dnp_request = DNP_Request.Issue_DNP_Command
    operation_param = DNP_Command.Link_Status
    prmFunCode, obj_def = TransmitFrame.dnpReq_generation(dnpReq=dnp_request, op_params=operation_param)
    appl_ctrl = TransmitFrame.getApplCtrl(obj_def)
    datalink_ctrl = TransmitFrame.getDataLinkReqCtrl(prmFunCode)
    while True:
        sleep(1)
        passed_time = datetime.now()-start_time
        if passed_time.total_seconds() >= 120:
            table, table_title = socket_conn.send(address, appl_ctrl, datalink_ctrl, obj_def)
            if table_title:
                add_items_to_treeview(table, table_title)
            start_time = datetime.now()
        if not stopToThreadQueue.empty():
            stopToThreadQueue.get()
            stopFromThreadQueue.put(False)
            # socket_conn.quit(conn_status_val)
            break

if __name__ == '__main__':
    unsolicitedMsgQueue = queue.Queue()
    stopToThreadQueue = queue.Queue()
    stopFromThreadQueue = queue.Queue()
    address = (52, 0)
    padding = {'padx': 5, 'pady': 5, 'sticky': tk.W}
    window = tk.Tk()
    window.geometry('700x800')
    window.resizable(False, False)
    window.title('DNP3 SCADA Master Simulator')
    # first is selection of comm protocol
    conn_frame = tk.LabelFrame(window, width=400, height=100)
    conn_frame.grid(column=0, row=0, **padding)
    protocol_label = ttk.Label(conn_frame, text='DNP Communication Protocol')
    protocol_label.grid(column=0, row=1, **padding)
    protocol_combo = ttk.Combobox(conn_frame, width=10, state='readonly')
    protocol_combo.grid(column=0, row=2, **padding)
    protocol_combo['values'] = ('UDP', 'TCP', 'Serial')
    protocol_combo.current(0)
    dnp_address_label = ttk.Label(conn_frame, text='DNP Address')
    dnp_address_label.grid(column=0, row=3, **padding)
    dnp_address_val = tk.StringVar()
    dnp_address_val.set('52')
    dnp_address_entry = ttk.Entry(conn_frame, textvariable=dnp_address_val)
    dnp_address_entry.grid(column=1, row=3, **padding)
    client_ip_label = ttk.Label(conn_frame, text='Client IP Address')
    client_ip_label.grid(column=0, row=4, **padding)
    client_ip_val = tk.StringVar()
    client_ip_val.set('192.168.52.2')
    client_ip_val_entry = ttk.Entry(conn_frame, textvariable=client_ip_val)
    client_ip_val_entry.grid(column=1, row=4, **padding)
    client_port_label = ttk.Label(conn_frame, text='Client Port')
    client_port_label.grid(column=0, row=5, **padding)
    client_port_val = tk.StringVar()
    client_port_val.set('20000')
    client_port_val_entry = ttk.Entry(conn_frame, textvariable=client_port_val)
    client_port_val_entry.grid(column=1, row=5, **padding)
    master_ip_label = ttk.Label(conn_frame, text='Master IP Address')
    master_ip_label.grid(column=0, row=6, **padding)
    master_ip_val = tk.StringVar()
    master_ip_val.set('192.168.52.201')
    master_ip_val_entry = ttk.Entry(conn_frame, textvariable=master_ip_val)
    master_ip_val_entry.grid(column=1, row=6, **padding)
    master_port_label = ttk.Label(conn_frame, text='Master Port')
    master_port_label.grid(column=0, row=7, **padding)
    master_port_val = tk.StringVar()
    master_port_val.set('20000')
    master_port_val_entry = ttk.Entry(conn_frame, textvariable=master_port_val)
    master_port_val_entry.grid(column=1, row=7, **padding)
    comport_name_label = ttk.Label(conn_frame, text='Com Port Name')
    comport_name_label.grid(column=0, row=8, **padding)
    comport_name_combo = ttk.Combobox(conn_frame, width=10, state='readonly')
    comport_name_combo.grid(column=1, row=8, **padding)
    comport_name_combo['values'] = [port_tuple[0] for port_tuple in serial.tools.list_ports.comports()]
    comport_name_combo.current(0)
    baudrate_label = ttk.Label(conn_frame, text='BaudRate')
    baudrate_label.grid(column=0, row=9, **padding)
    baudrate_val = tk.StringVar()
    baudrate_val.set('57600')
    baudrate_entry = ttk.Entry(conn_frame, textvariable=baudrate_val)
    baudrate_entry.grid(column=1, row=9, **padding)
    dnpMaster = None
    thread_1 = None
    thread_2 = None
    def connect_to_client():
        global dnpMaster, thread_1, thread_2
        dnpAddress = int(dnp_address_entry.get())   # int type
        clientIpAddress = client_ip_val_entry.get()
        clientPortNum = int(client_port_val_entry.get())
        masterIpAddress = master_ip_val_entry.get()
        masterPortNum = int(master_port_val_entry.get())
        commProtocol = protocol_combo.get().lower()
        comPortName = comport_name_combo.get()
        baudRateVal = 0
        if baudrate_entry.get().isnumeric():
            baudRateVal = int(baudrate_entry.get())
        dnpMaster = dnp3master(dnp_address=dnpAddress, client_ip=clientIpAddress, client_port=clientPortNum, master_ip=masterIpAddress, 
        master_port=masterPortNum, buffer_size=1024, method=commProtocol, com_port_name=comPortName, baud_rate=baudRateVal)
        if dnpMaster != None:
            cmd_frame.grid(column=0, row=13, **padding)
            cmd_combo.current(8)
            arg_combo.grid_forget()
            optional_arg_entry.grid_forget()
            dnpMaster.logger.setLevel("DEBUG")
            indicator = dnpMaster.run(conn_status_val)  # Connect to outstation
            if indicator:
                conn_status_entry.configure(bg=indicator)
            thread_1 = threading.Thread(target=read_from_socket, args=(dnpMaster, address, unsolicitedMsgQueue, stopToThreadQueue, stopFromThreadQueue), daemon=True)
            thread_2 = threading.Thread(target=check_link_status, args=(dnpMaster, address, stopToThreadQueue, stopFromThreadQueue),daemon=True)
            stopToThreadQueue.queue.clear()
            stopFromThreadQueue.queue.clear()
            thread_1.start()
            thread_2.start()
            for child in conn_frame.winfo_children():
                if child.widgetName != 'ttk::label':
                    if child.cget('text') != 'Disconnect':
                        child.configure(state='disable')
                    else:
                        child.configure(state='enable')
            for item in tree.get_children():
                tree.delete(item)
    conn_button = ttk.Button(conn_frame, text='Connect', command = connect_to_client)
    conn_button.grid(column=2, row=2, **padding)  

    def disconnect_from_client(stopToThreadQueue, stopFromThreadQueue, conn_status_val, conn_status_entry, *argv):
        disconn_button.config(cursor='watch')
        window.update_idletasks()
        cmd_frame.grid_forget()
        stopToThreadQueue.put(conn_status_val)
        stopToThreadQueue.put(conn_status_val)
        for arg in argv:
            arg.join()
        stopFromThreadQueue.get(timeout=10.0)
        stopFromThreadQueue.get(timeout=10.0)
        indicator = dnpMaster.quit(conn_status_val)
        if indicator:
            conn_status_entry.configure(bg=indicator)
        for child in conn_frame.winfo_children():
            if child.widgetName != 'ttk::label':
                if child.cget('text') != 'Disconnect':
                    child.configure(state='enable')
                else:
                    child.configure(state='disable')
        disconn_button.config(cursor='')
    disconn_button = ttk.Button(conn_frame, text='Disconnect', command = lambda: 
    disconnect_from_client(stopToThreadQueue, stopFromThreadQueue, conn_status_val, conn_status_entry, thread_1, thread_2))
    disconn_button.configure(state='disable')
    disconn_button.grid(column=3, row=2, **padding)

    dnp_msg_label = ttk.Label(window, text='DNP Message Display')
    dnp_msg_label.grid(column=0, row=10, **padding)

    style = ttk.Style()
    style.element_create("Custom.Treeheading.border", "from", "default")
    style.layout("Custom.Treeview.Heading", [
        ("Custom.Treeheading.cell", {'sticky': 'nswe'}),
        ("Custom.Treeheading.border", {'sticky':'nswe', 'children': [
            ("Custom.Treeheading.padding", {'sticky':'nswe', 'children': [
                ("Custom.Treeheading.image", {'side':'right', 'sticky':''}),
                ("Custom.Treeheading.text", {'sticky':'we'})
            ]})
        ]}),
    ])
    style.configure("Custom.Treeview.Heading",
        background="blue", foreground="white", relief="flat")
    style.map("Custom.Treeview.Heading",
        relief=[('active','groove'),('pressed','sunken')])

    tree = ttk.Treeview(window, style='Custom.Treeview', height=12)
    tree['columns'] = ('Value')
    tree.column('#0', width=450)
    tree.column('Value', width=200)
    tree.heading('#0', text='Name')
    tree.heading('Value', text='Value')
    tree.grid(column=0, row=11, **padding)
    scrollbar = ttk.Scrollbar(window, orient=tk.VERTICAL, command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    scrollbar.grid(column=1, row=11, sticky='ns')

    tree_item_index = 0
    def add_items_to_treeview(table, title):
        global tree_item_index
        table = {title: table}
        tree_item_list = []
        buffer_list = []
        first_item = [-1, -1, table]
        buffer_list.append(first_item)
        while buffer_list:
            first_item = buffer_list.pop()
            if isinstance(first_item[2], dict):
                for key, value in first_item[2].items():
                    if isinstance(value, dict):
                        buffer_list.append([first_item[1], tree_item_index, value])
                        tree_item_list.append([first_item[1], tree_item_index, key])
                    else:
                        tree_item_list.append([first_item[1], tree_item_index, (key, value)])
                    tree_item_index += 1
        for tree_item in tree_item_list:
            if tree_item[0] == -1:   # this is the root item, no parent
                tree.insert('', 'end', iid=tree_item[1], text=tree_item[2], values=(''), open=False)
            else:
                if isinstance(tree_item[2], tuple):
                    treeItem_val = tree_item[2][1]
                    if isinstance(tree_item, int):
                        treeItem_val = str(treeItem_val)
                    tree.insert(tree_item[0], 'end', iid=tree_item[1], text=tree_item[2][0], values=(treeItem_val,), open=False)
                else:
                    tree.insert(tree_item[0], 'end', iid=tree_item[1], text=tree_item[2], values=(''), open=False)
        tree_item_index += len(tree_item_list)
        tree.yview_moveto(1)    # display the bottom of the table
    
    def get_all_children(tree, item=""):
        children = tree.get_children(item)
        for child in children:
            children += get_all_children(tree, child)
        return children   

    conn_status_val = tk.StringVar()
    conn_status_entry = tk.Entry(window, width=105, textvariable=conn_status_val)
    conn_status_entry.grid(column=0, row=12, columnspan=3, **padding)

    cmd_frame = Labelframe(window, width=1200, height=300)
    cmd_frame.grid(column=0, row=13, **padding)
    cmd_combo_label = ttk.Label(cmd_frame, text="Please select a DNP requisition command:")
    cmd_combo_label.grid(column=0, row=0, **padding)
    cmd_combo = ttk.Combobox(cmd_frame, width=30, state='readonly')
    cmd_combo.grid(column=0, row=1, **padding)
    cmd_combo['values'] = [dnp_req.name for dnp_req in DNP_Request]
    cmd_combo.current(8)
    optional_arg = tk.StringVar()
    optional_arg_entry = ttk.Entry(cmd_frame, width=80, textvariable=optional_arg)
    optional_arg_entry.grid(column=0, row=2, columnspan=3, **padding)
    arg_combo = ttk.Combobox(cmd_frame, width=30, state='readonly')
    arg_combo.grid(column=0, row=2, **padding)
    arg_combo['values'] = [dnp_cmd.name for dnp_cmd in DNP_Command]
    arg_combo.current(33)

    def issue_request(dnpMaster):
        selected_dnpreq = cmd_combo.get()
        optional_args = optional_arg_entry.get()
        dnp_cmd_args = arg_combo.get()
        userInputArray = [x for x in optional_args.strip().split(' ') if ' ' not in x and x!='']
        dnp_request = DNP_Request[selected_dnpreq]
        if dnp_request == DNP_Request.Issue_DNP_Command:
            operation_param = DNP_Command[dnp_cmd_args]
        elif dnp_request in  [DNP_Request.Read_Binary_Output_Points, DNP_Request.Read_Analog_Output_Points, DNP_Request.Read_Counter_Points]:
            operation_param = None
        elif dnp_request in  [DNP_Request.Read_Binary_Input_Points, DNP_Request.Read_Analog_Intput_Points]:
            if len(userInputArray) == 0:
                operation_param = None
            else:
                operation_param = [x.strip() for x in userInputArray]
        elif dnp_request == DNP_Request.Write_Control_Operation_Point:
            operationStr = userInputArray[0].strip()
            pointStr = userInputArray[1].strip()
            operation_param = (Operation[operationStr], int(pointStr))
        elif dnp_request == DNP_Request.Write_Analog_Output_Point:
            # variation, point, newVal
            varStr = userInputArray[0].strip()
            pointStr = userInputArray[1].strip()
            newvalStr = userInputArray[2].strip()
            operation_param = (int(varStr), int(pointStr), float(newvalStr))
        else:       # this needs more code to handle manual dnp request
            pass   
        prmFunCode, obj_def = TransmitFrame.dnpReq_generation(dnpReq=dnp_request, op_params=operation_param)
        appl_ctrl = TransmitFrame.getApplCtrl(obj_def)
        datalink_ctrl = TransmitFrame.getDataLinkReqCtrl(prmFunCode)
        table, table_title = dnpMaster.send(address, appl_ctrl, datalink_ctrl, obj_def)
        if table_title:
            add_items_to_treeview(table, table_title)
        
    issue_dnpreq_btn = ttk.Button(cmd_frame, text='Send Request', command=lambda: issue_request(dnpMaster))
    issue_dnpreq_btn.grid(column=1, row=1, **padding)
    cmd_frame.grid_forget()

    def req_change(event):
        """ handle the dnp requisition command changed event """
        selected_dnpreq = cmd_combo.get()
        if '_Point' in selected_dnpreq:   # add option argument to read/write single point value
            arg_combo.grid_forget()
            optional_arg_entry.grid(column=0, row=2, columnspan=3, **padding)
        elif selected_dnpreq == 'Issue_DNP_Command':
            optional_arg_entry.grid_forget()
            arg_combo.grid(column=0, row=2, **padding)
        else:
            arg_combo.grid_forget()
            optional_arg_entry.grid_forget()        
    cmd_combo.bind('<<ComboboxSelected>>', req_change)

    window.mainloop()
