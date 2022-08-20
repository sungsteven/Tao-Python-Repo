from struct import pack, unpack
import binascii
from datetime import datetime, timedelta
from DNP3_SC.utils import *

__author__ = 'Tao Sun'
__version__ = '1.0.0'


refTime = datetime(2000, 1, 1)

class TransmitFrame():
    '''
    ## Request Frame  ##
    ## This class represents a frame being sent out as request 

    '''
    def __init__(self, address, appl_ctrl, datalink_ctrl, obj_def):
        self.start_octets = bytes.fromhex('0564')
        self.remote_address = TransmitFrame.swapBytes(address[0])
        self.master_address = TransmitFrame.swapBytes(address[1])
        self.datalink_ctrl = datalink_ctrl.to_bytes(1, 'big')
        dataBlocks, lenOfFinalDB = self.set_data_blocks(obj_def)        # this function also sets value to self.data_blocks
        self.len = (lenOfFinalDB+5+(dataBlocks-1)*16).to_bytes(1, 'big')
        self.crc_dl = TransmitFrame.calculateCRC(self.start_octets+self.len+self.datalink_ctrl+self.remote_address+self.master_address)
        if len(obj_def['Object Info']) != 0 or obj_def['Function Codes'] != Function_Code.READ:
            this_transIndex = transport_index_global(oper_mode=Operation_Mode.Get)
            self.transport_header = (this_transIndex | 0b11000000).to_bytes(1, 'big')
            self.appl_ctrl = appl_ctrl.to_bytes(1, 'big')
            self.appl_func_code = obj_def["Function Codes"].value.to_bytes(1, 'big')
            data_block = dict()
            if len(self.data_blocks) != 0:
                data_block = self.data_blocks[0]
                data_block['CRC'] = TransmitFrame.calculateCRC(self.transport_header+self.appl_ctrl+self.appl_func_code+data_block['User Data'])
                self.data_blocks[0] = data_block
            else:
                data_block = dict()
                data_block['CRC'] = TransmitFrame.calculateCRC(self.transport_header+self.appl_ctrl+self.appl_func_code)
                data_block['User Data'] = b''
                self.data_blocks = [data_block]
            self.valid_obj = True
        else:
            self.valid_obj = False
            self.transport_header = b''
            self.appl_ctrl = b''
            self.appl_func_code = b''

    def convert2bytes(self):
        if hasattr(self, 'data_blocks'):
            data_blocks_bytes = b''.join([b''.join([data for data in list(data_block.values())]) for data_block in self.data_blocks])
            return self.start_octets + self.len + self.datalink_ctrl + self.remote_address + self.master_address + self.crc_dl\
                + self.transport_header + self.appl_ctrl + self.appl_func_code + data_blocks_bytes
        else:
            return self.start_octets + self.len + self.datalink_ctrl + self.remote_address + self.master_address + self.crc_dl

    def set_data_blocks(self, obj_def):
        '''
        the input argument obj_definition is a dictionary with following two keys,
        * ``Function Codes``, is an enumerator
        * ``Object Info``, is a list of dictionary with up to five following keys
            ** ``Object``
            ** ``Variation``
            ** ``Qualifier``
            ** ``Range``
            ** ``Data``
            all of values should be bytes (but without b'' format) if defined
        '''
        self.data_blocks = []
        dataBlocks = 1
        lenOfFinalDB = 0
        oversizeDB = False
        if len(obj_def['Object Info']) != 0:
            datablock_dict = dict()
            userData_bytes = b''
            for obj in obj_def['Object Info']:  # obj_definition is a list of dict
                userData_bytes += b''.join([bytes.fromhex(data) for data in list(obj.values())])
            datablock_dict['User Data'] = userData_bytes[:13]
            self.data_blocks.append(datablock_dict)
            lenOfFinalDB = len(userData_bytes) + 3
            oversizeDB = (lenOfFinalDB >= 16)
        else:
            if obj_def['Function Codes'].value in [0, 13, 23, 24]:
                lenOfFinalDB = 3
        if oversizeDB:
            data_bytes = userData_bytes[13:]
            datablock_dict_2 = dict()
            index = 0
            while True:
                first_bytes = data_bytes[:16]
                datablock_dict_2['User Data'] = first_bytes
                datablock_dict_2['CRC'] = TransmitFrame.calculateCRC(first_bytes)
                self.data_blocks.append(datablock_dict_2)
                if len(data_bytes) > 16:
                    data_bytes = data_bytes[16:]
                    index += 1
                else:
                    break
            lenOfFinalDB = len(data_bytes)
            dataBlocks = index + 2
        else:
            dataBlocks = 1
        return (dataBlocks, lenOfFinalDB)

    @staticmethod
    def calculateCRC(data_byte_list):       # input is type of bytes (b'')
        crcVal = 0
        for dataByte in data_byte_list:
            for index in range(8):
                if ((dataByte ^ crcVal) & 1) != 0:
                    crcVal =  (crcVal >> 1) ^ 0xa6bc
                else:
                    crcVal = crcVal >> 1
                dataByte = dataByte >> 1
        return (int.from_bytes(TransmitFrame.swapBytes(crcVal), 'big') ^ 0xffff).to_bytes(2, 'big')

    @staticmethod
    def swapBytes(inputInt):
        inputInt_bytes = inputInt.to_bytes(2, 'big')
        return inputInt_bytes[1:] + inputInt_bytes[:1]

    @staticmethod
    def getApplCtrl(obj_def, unsolicited=False):
        if len(obj_def['Object Info']) != 0:
            if unsolicited:
                return unsolicitRespSeq_index_global(oper_mode=Operation_Mode.Get) | 0b11010000
            else:
                return solicitRespSeq_index_global(oper_mode=Operation_Mode.Get) | 0b11000000
        else:
            return (0b11010000 if unsolicited else 0b11000000)

    @staticmethod
    def getDataLinkReqCtrl(prm1_funcCode):
        prm1_funcVal = PRM1_Func_Code(prm1_funcCode).value
        funcTable = [list(x) for x in zip(*PRM1FUNCTIONCODES)]
        return (int(funcTable[3][funcTable[0].index(str(prm1_funcVal))]) << 4) | 0b11000000 | prm1_funcVal

    @staticmethod
    def config_ctrlPoint(operation, point, count=1, on_time=0, off_time=0):
        '''
        Input parameters:
        * ``operation``: Enum type of Operation
        * ``count``: one byte integer
        * ``on_time``: U32 integer
        * ``off_time``: U32 integer
        * ``point``: one byte integer
        '''
        obj_def = {'Function Codes': Function_Code.DIRECT_OPERATE, 'Object Info': [{'Object': '0C', 'Variation': '01', 'Qualifier': '17'}]}
        obj_def['Object Info'][0]['Range'] = f'{int(1):02x}' + f'{point:02x}'
        data_bytes = b''
        if operation == Operation.Close:
            tccCode = TCC_Code.Close
            opTypeCode = Op_Type_Code.Pulse_On
        elif operation == Operation.Pulse_On:
            tccCode = TCC_Code.Null
            opTypeCode = Op_Type_Code.Pulse_On
        elif operation == Operation.Pulse_Off:
            tccCode = TCC_Code.Null
            opTypeCode = Op_Type_Code.Pulse_Off
        elif operation == Operation.Latch_On:
            tccCode = TCC_Code.Null
            opTypeCode = Op_Type_Code.Latch_On
        elif operation == Operation.Latch_Off:
            tccCode = TCC_Code.Null
            opTypeCode = Op_Type_Code.Latch_Off
        else:
            tccCode = TCC_Code.Trip
            opTypeCode = Op_Type_Code.Pulse_On   
        data_bytes += ((tccCode.value << 6) | opTypeCode.value).to_bytes(1, 'big')
        data_bytes += count.to_bytes(1, 'big')
        data_bytes += on_time.to_bytes(4, 'big')
        data_bytes += off_time.to_bytes(4, 'big')
        data_bytes += Ctrl_Status_Code.SUCCESS.value.to_bytes(1, 'big')
        obj_def['Object Info'][0]['Data'] = data_bytes.hex()
        return obj_def

    @staticmethod
    def config_analogPoint(variation, point, newVal):
        '''
        Input parameters:
        * ``variation``: one byte integer
        * ``point``: one byte integer
        * ``newVal``: floating point 
        '''
        obj_def = {'Function Codes': Function_Code.DIRECT_OPERATE, 'Object Info': [{'Object': '29', 'Variation': '01', 'Qualifier': '17'}]}
        obj_def['Object Info'][0]['Range'] = f'{int(1):02x}' + f'{point:02x}'
        obj_def['Object Info'][0]['Variation'] = f'{variation:02x}'
        data_bytes = b''
        ctrlStatusVal = 0
        if variation == 1:          # 32 bit
            data_bytes += ctrlStatusVal.to_bytes(1, 'big')
            data_bytes += bytes.fromhex(f'{int(newVal):08x}')
            data_bytes = bytes(reversed(bytearray(data_bytes)))
        elif variation == 2:          # 16 bit
            data_bytes += ctrlStatusVal.to_bytes(1, 'big')
            data_bytes += bytes.fromhex(f'{int(newVal):04x}')
            data_bytes = bytes(reversed(bytearray(data_bytes)))
        elif variation == 3:          # Single-precision floating-point
            data_bytes += pack('!f', newVal)
            data_bytes += ctrlStatusVal.to_bytes(1, 'big')
        elif variation == 4:          # double-precision floating-point
            data_bytes += pack('!d', newVal)
            data_bytes += ctrlStatusVal.to_bytes(1, 'big')      
        obj_def['Object Info'][0]['Data'] = data_bytes.hex()
        return obj_def

    @staticmethod
    def issue_dnp_cmd(dnpCmd):
        global refTime
        if dnpCmd == DNP_Command.Class_1_Data:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '3C', 'Variation': '02', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Class_2_Data:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '3C', 'Variation': '03', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Class_3_Data:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '3C', 'Variation': '04', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Class_0_Data:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '3C', 'Variation': '01', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Class_1_2_3_0_Data:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '3C', 'Variation': '02', 'Qualifier': '06'}, 
            {'Object': '3C', 'Variation': '03', 'Qualifier': '06'},
            {'Object': '3C', 'Variation': '04', 'Qualifier': '06'},
            {'Object': '3C', 'Variation': '01', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Enable_Unsolicited_Response:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.ENABLE_UNSOLICITED, 'Object Info': [{'Object': '3C', 'Variation': '02', 'Qualifier': '06'}, 
            {'Object': '3C', 'Variation': '03', 'Qualifier': '06'},
            {'Object': '3C', 'Variation': '04', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Disable_Unsolicited_Response:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.DISABLE_UNSOLICITED, 'Object Info': [{'Object': '3C', 'Variation': '02', 'Qualifier': '06'}, 
            {'Object': '3C', 'Variation': '03', 'Qualifier': '06'},
            {'Object': '3C', 'Variation': '04', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Binary_Input_Status:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '01', 'Variation': '00', 'Qualifier': '06'}]}      
        elif dnpCmd == DNP_Command.Device_Attributes:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '00', 'Variation': 'FE', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Reset_Link:
            prmFunCode = PRM1_Func_Code.RESET_LINK_STATES
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': []}
        elif dnpCmd == DNP_Command.Binary_Input_Change:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '02', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Binary_Input_Changes_and_Current_States:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '02', 'Variation': '00', 'Qualifier': '06'},
            {'Object': '02', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Binary_Output_Status:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '0A', 'Variation': '00', 'Qualifier': '06'}]} 
        elif dnpCmd == DNP_Command.Binary_Output_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '0B', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Binary_Output_Command_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '0D', 'Variation': '00', 'Qualifier': '06'}]}  
        elif dnpCmd == DNP_Command.Binary_Counter:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '14', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Frozen_Counter:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '15', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Binary_Counter_Change:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '16', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Frozen_Counter_Change:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '17', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Analog_Input_Status:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '1E', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Frozen_Analog_Input:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '1F', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Analog_Change_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '20', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Frozen_Analog_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '21', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Analog_Output_Status:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '28', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Analog_Output_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '2A', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Analog_Output_Command_Event:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '2B', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Read_Analog_Deadbands:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '22', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Security_Statistics:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '79', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Security_Statistics_Events:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '7A', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpCmd == DNP_Command.Clear_Restart:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.WRITE, 'Object Info': [{'Object': '22', 'Variation': '00', 'Qualifier': '06', 'Range': '0707', 'Data': '00'}]}
        elif dnpCmd == DNP_Command.Warm_Restart:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.WARM_RESTART, 'Object Info': []}
        elif dnpCmd == DNP_Command.Cold_Restart:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.COLD_RESTART, 'Object Info': []}
        elif dnpCmd == DNP_Command.Time_Synchronization:
            if refTime == datetime(2000, 1, 1):
                prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
                obj_def = {'Function Codes': Function_Code.RECORD_CURRENT_TIME, 'Object Info': []}
                refTime = datetime.now()
            else:    
                prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
                obj_def = {'Function Codes': Function_Code.WRITE, 'Object Info': [{'Object': '32', 'Variation': '03', 'Qualifier': '07', 'Range': '01'}]}
                time_int = int((refTime-datetime(1970,1,1)).total_seconds()*1000)
                timedate_bytes = b''
                for index in range(6):
                    if index != 0:
                        time_int = time_int >> 8
                    timedate_bytes += (time_int & 0x00ff).to_bytes(1, 'big')
                obj_def['Object Info'][0]['Data'] = timedate_bytes.hex()
                refTime = datetime(2000, 1, 1)
        else:
            prmFunCode = PRM1_Func_Code.REQUEST_LINK_STATUS
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': []}    
        return (prmFunCode, obj_def)

    @staticmethod
    def dnpReq_generation(dnpReq, op_params=None):
        if dnpReq == DNP_Request.Read_Binary_Input_Points:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            if op_params == None:               # request to read all points in this group 
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '01', 'Variation': '00', 'Qualifier': '06'}]}
            elif len(op_params) == 1:           # request to read only one point in this group
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '01', 'Variation': '01', 'Qualifier': '00'}]}
                obj_def['Object Info'][0]['Range'] = f'{int(op_params[0]):02x}'*2
            else:                               # request to read a range of points in this group
                variation_str = op_params[0]
                qualifier_str = op_params[1][:2]
                range_str = op_params[1][2:]
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '01', 'Variation': variation_str, 'Qualifier': qualifier_str}]}
                obj_def['Object Info'][0]['Range'] = range_str 
        elif dnpReq == DNP_Request.Read_Binary_Output_Points:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '0A', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpReq == DNP_Request.Read_Analog_Intput_Points:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            if op_params == None:               # request to read all points in this group
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '1E', 'Variation': '00', 'Qualifier': '06'}]}
            elif len(op_params) == 1:           # request to read only one point in this group
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '1E', 'Variation': '01', 'Qualifier': '00'}]}
                obj_def['Object Info'][0]['Range'] = f'{int(op_params[0]):02x}'*2
            else:                               # request to read a range of points in this group
                variation_str = op_params[0]
                qualifier_str = op_params[1][:2]
                range_str = op_params[1][2:]
                obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '1E', 'Variation': variation_str, 'Qualifier': qualifier_str}]}
                obj_def['Object Info'][0]['Range'] = range_str    
        elif dnpReq == DNP_Request.Read_Analog_Output_Points:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '28', 'Variation': '00', 'Qualifier': '06'}]}  
        elif dnpReq == DNP_Request.Read_Counter_Points:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '14', 'Variation': '00', 'Qualifier': '06'}]}
        elif dnpReq == DNP_Request.Write_Control_Operation_Point:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = TransmitFrame.config_ctrlPoint(operation=op_params[0], point=op_params[1])   
        elif dnpReq == DNP_Request.Write_Analog_Output_Point:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = TransmitFrame.config_analogPoint(op_params[0], op_params[1], op_params[2])
        elif dnpReq == DNP_Request.Issue_DNP_Command:
            prmFunCode, obj_def = TransmitFrame.issue_dnp_cmd(op_params)
        else:
            prmFunCode = PRM1_Func_Code.UNCONFIRMED_USER_DATA
            obj_def = op_params
        return (prmFunCode, obj_def)

class ReceivedFrame():
    '''
    ## This class represents a frame being received either upon request (solicited) or broadcasting (unsolicited)
    '''
    # global bytes_to_nextFrag
    def __init__(self, data_bytes, isFirstFragment=True, datablock_bytes=None, isReqFrame=False):
        self.set_datalink_header(data_bytes)
        # transport_header and app_header are only available when data_bytes length is more than 10
        if datablock_bytes != None:
            self.set_transport_header(data_bytes[10:], isFirstFragment, isReqFrame)
            self.set_app_data(datablock_bytes, isFirstFragment, isReqFrame)
        elif len(data_bytes) > 10:
            self.set_transport_header(data_bytes[10:], isFirstFragment, isReqFrame)

    def set_datalink_header(self, byte_data):
        '''
        Output parameter datalink_header is a dict type that should have following structure
        ** ``length``: int
        ** ``control``: a dictionary that consists of 
                        ``value``: one byte hex
                        ``user_data``: an PRM2 enum
                        ``FCV``: one bit
                        ``FCB``: one bit
                        ``PRM``: one bit
                        ``DIR``: one bit
        ** ``dest``: int
        ** ``source``: int
        '''
        # print(byte_data)
        # print(binascii.hexlify(byte_data))
        self.datalink_header = dict()
        # self.datalink_header['Length'] = byte_data[2]
        self.datalink_header['Length'] = int.from_bytes(byte_data[2:3], 'big')
        self.datalink_header['Control'] = dict()
        control_val = byte_data[3]
        user_data_val = int(f'{control_val:08b}'[4:], 2)
        control_bits = f'{control_val:08b}'[:4][::-1]
        self.datalink_header['Control']['Value'] = f'0x{control_val:02X}'
        if control_bits[2] == '1':      # PRM=1
            self.datalink_header['Control']['User_Data'] = PRM1_Func_Code(user_data_val).name
        else:
            self.datalink_header['Control']['User_Data'] = PRM0_Func_Code(user_data_val).name
        self.datalink_header['Control']['FCV'] = int(control_bits[0])
        self.datalink_header['Control']['FCB'] = int(control_bits[1])
        self.datalink_header['Control']['PRM'] = int(control_bits[2])
        self.datalink_header['Control']['DIR'] = int(control_bits[3])
        self.datalink_header['Dest'] = int.from_bytes(byte_data[5:6]+byte_data[4:5], 'big')
        self.datalink_header['Source'] = int.from_bytes(byte_data[7:8]+byte_data[6:7], 'big')

    def set_transport_header(self, byte_data, isFirstSeg=True, isReqFrame=False):
        # This is for transport header
        thVal = byte_data[0]
        self.transport_header = dict()
        self.transport_header['Control'] = dict()
        self.transport_header['Control']['Value'] = f'0x{thVal:02X}'
        self.transport_header['Control']['Seq'] = int(f'{thVal:08b}'[::-1][:6], 2)
        self.transport_header['Control']['FIR'] = int(f'{thVal:08b}'[::-1][6])
        self.transport_header['Control']['FIN'] = int(f'{thVal:08b}'[::-1][7])
        if isFirstSeg:
        # The following is the front of application header (before Object header)
            control_val = byte_data[1]
            seq_val = int(f'{control_val:08b}'[4:], 2)
            control_bits = f'{control_val:08b}'[:4][::-1]
            self.application_data = dict()
            self.application_data['Control'] = dict()
            self.application_data['Control']['Value'] = f'0x{control_val:02X}'
            self.application_data['Control']['Seq'] = seq_val
            self.application_data['Control']['UNS'] = int(control_bits[0])
            self.application_data['Control']['CON'] = int(control_bits[1])
            self.application_data['Control']['FIN'] = int(control_bits[2])
            self.application_data['Control']['FIR'] = int(control_bits[3])
            function_val = byte_data[2]
            self.application_data['Function'] = f'{function_val} ({Function_Code(function_val).name})'
            if not isReqFrame:
                self.application_data['Internal Indicator'] = dict()
                iin_val = int.from_bytes(byte_data[3:5], 'big')
                self.application_data['Internal Indicator']['Value'] = f'0x{iin_val:04X}'
                iin_bits = f'{iin_val:016b}'[::-1][8:] + f'{iin_val:016b}'[::-1][:8]
                iin_bitNames = ['IIN1.0 All Station', 'IIN1.1 Class 1', 'IIN1.2 Class 2', 'IIN1.3 Class 3', 
                'IIN1.4 Need Time', 'IIN1.5 Local', 'IIN1.6 Trouble', 'IIN1.7 Restart', 'IIN2.0 Bad FC', 
                'IIN2.1 Obj Unknown', 'IIN2.2 Param Invalid', 'IIN2.3 Buffer Overflow', 'IIN2.4 Already Active', 
                'IIN2.5 Bad Config', 'IIN2.6 Reserve', 'IIN2.7 Reserve']
                for index in range(16):
                    self.application_data['Internal Indicator'][iin_bitNames[index]] = int(iin_bits[index])

    def set_app_data(self, byte_data, isFirstSeg=True, isReqFrame=False):
        # original_byte_count = len(byte_data)
        if not isFirstSeg:
            byte_data = leftover_bytes_global(oper_mode=Operation_Mode.Get) + byte_data
        # extra_bytes_count = len(byte_data) - self.datalink_header['Length'] + 6
        if not isReqFrame:
            isNewObject = not object_data_tuple_global(oper_mode=Operation_Mode.Get)[0]
            start_object_index = object_data_tuple_global(oper_mode=Operation_Mode.Get)[1]
            object_count = object_data_tuple_global(oper_mode=Operation_Mode.Get)[2]
        # The first segment is for object header
        while True:
            array_size = len(byte_data)
            groupVal = byte_data[0]
            variationVal = byte_data[1]
            groupStr = list(GROUP_VARIATION_DICT[str(groupVal)].values())[0].split('_')[0]
            variationStr = ''
            if str(variationVal) in GROUP_VARIATION_DICT[str(groupVal)].keys():
                variationStr = GROUP_VARIATION_DICT[str(groupVal)][str(variationVal)].split('_')[1]
            appDataDict = f'{groupStr} (Object {groupVal})'
            if not hasattr(self, 'application_data'):
                self.application_data = dict()
            if appDataDict not in self.application_data.keys():
                self.application_data[appDataDict] = dict()
            self.application_data[appDataDict][f'Object {groupVal}'] = groupStr
            self.application_data[appDataDict][f'Var {variationVal}'] = variationStr
            qualifierVal = byte_data[2]
            self.application_data[appDataDict]['Qualifier'] = dict()
            self.application_data[appDataDict]['Qualifier']['Value'] = f'0x{qualifierVal:02X}'
            
            prefix_size = 0
            start_index = -1
            stop_index = -1
            show_count = True
            data_size = 0
            divider = 0
            count_out = 0
            if qualifierVal == 1:           # 0x01, 2-octet start-stop indexes
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '1: Range field contains 2-octet start and stop indexes'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '0: Objects are packed without an index prefix'
                start_index = int.from_bytes(byte_data[4:5]+byte_data[3:4], 'big')
                stop_index = int.from_bytes(byte_data[6:7]+byte_data[5:6], 'big')
                count = stop_index - start_index + 1
                obj_index = 7
                show_count = False
            elif qualifierVal == 7:         # 0x07, 1-octet count of objects
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '7: Range field contains 1-octet count of objects'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '0: Objects are packed without an index prefix'
                count = byte_data[3]
                obj_index = 4
                show_count = False
            elif qualifierVal == 8:         # 0x08, 2-octet count of objects
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '8: Range field contains 2-octet count of objects'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '0: Objects are packed without an index prefix'
                count = int.from_bytes(byte_data[9:10]+byte_data[8:9], 'big')
                obj_index = 5
            elif qualifierVal == 6:         # 0x06, No range field'
                self.application_data[appDataDict]['Qualifier']['0000110'] = 'All points'
                if not isReqFrame:
                    count = byte_data[3]
                else:
                    count = 0
                obj_index = 4
                show_count = False
            elif qualifierVal == 23:        # 0x17, 1-octet count of objects
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '7: Range field contains 1-octet count of objects'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '1: Objects are prefixed with an index'
                count = byte_data[3]
                obj_index = 4
                prefix_size = 1
            elif qualifierVal == 40:        # 0x28, 2-octet count of objects
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '8: Range field contains 2-octet count of objects'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '2: Objects are prefixed with an index'
                count = int.from_bytes(byte_data[9:10]+byte_data[3:4], 'big')
                obj_index = 5
                prefix_size = 2
            elif qualifierVal == 91:        # 0x5B, 1-octet count of objects
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = 'B: Variable format qualifier, range field contains 1-octet count of objects'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '5: Objects are prefixed with an object size'
                count = byte_data[3]
                obj_index = 4
                prefix_size = 2
            else:                           # 0x00, 1-octet start-stop indexes
                self.application_data[appDataDict]['Qualifier']['Range Specifier Code'] = '0: Range field contains 1-octet start and stop indexes'
                self.application_data[appDataDict]['Qualifier']['Object prefix code'] = '0: Objects are packed without an index prefix'
                start_index = byte_data[3]
                stop_index = byte_data[4]
                count = stop_index - start_index + 1
                obj_index = 5
            if not isFirstSeg:
                start_index = start_object_index
                count = object_count
                isFirstSeg = True
            if start_index != -1:
                self.application_data[appDataDict]['Start Index'] = start_index
                self.application_data[appDataDict]['Stop Index'] = stop_index
            if show_count:
                self.application_data[appDataDict]['Count'] = count
            if not isReqFrame:
                self.application_data[appDataDict]['Object Data'] = dict()
            if groupVal in [1, 3, 10]:      # Binary Inputs, Double-bit Binary Inputs, or Binary Outputs
                if groupVal == 3:         # Double-bit Binary Inputs
                    groupName = 'DblBit_BI'
                    if variationVal == 1:   # Packed Format
                        quotient, remainder = divmod(count, 4)
                        count_out = quotient+1 if remainder > 0 else quotient
                        divider = 4
                        data_size = 1
                    elif variationVal == 2: # With Flags
                        divider = 1
                        data_size = prefix_size + 1
                        count_out = count
                else:                       # Binary Inputs or Binary Outputs
                    groupName = 'BI' if groupVal == 1 else 'BO'
                    if variationVal == 1:   # Packed Format
                        quotient, remainder = divmod(count, 8)
                        count_out = quotient+1 if remainder > 0 else quotient
                        divider = 8
                        data_size = 1
                    elif variationVal == 2: # With Flags
                        divider = 1
                        data_size = prefix_size + 1
                        count_out = count
                array_size_process, count_process, left_to_nextFrag = ReceivedFrame.check_ifAllInSeg(array_size, obj_index, data_size, count_out)
                new_count = min(count, count_process*divider)
                bytes_process = byte_data[:(3 if (variationVal==0 and qualifierVal==6) else array_size_process)]
                if obj_index < len(bytes_process):
                    data_readout = ReceivedFrame.read_bioStatus(groupVal, variationVal, bytes_process, obj_index, start_index, prefix_size, new_count)
                    for data in data_readout:
                        self.application_data[appDataDict]['Object Data'][f'{groupName} {data[0]}'] = data[1]
            elif groupVal in [2, 4, 11, 13]:    # Binary Input Events, Double-bit Binary Input Events, Binary Output Events, or Binary Output Command Events
                if groupVal == 2:               # Binary Input Events
                    groupName = 'BI_Evt'
                    if variationVal == 1:       # Without Time
                        data_size = prefix_size + 1
                    elif variationVal == 2:     # With Absolute Time
                        data_size = prefix_size + 7
                    elif variationVal == 3:     # With Relative Time
                        data_size = prefix_size + 3
                    else:
                        data_size = 0 
                elif groupVal == 4:             # Double-bit Binary Input Events
                    groupName = 'DblBit_BI_Evt'
                    if variationVal == 1:       # Without Time
                        data_size = prefix_size + 1
                    elif variationVal == 2:     # With Absolute Time
                        data_size = prefix_size + 7
                    elif variationVal == 3:     # With Relative Time
                        data_size = prefix_size + 3
                    else:
                        data_size = 0
                elif groupVal == 11:            # Binary Output Events
                    groupName = 'BO_Evt'
                    if variationVal == 1:       # Without Time
                        data_size = prefix_size + 1
                    elif variationVal == 2:     # With Time
                        data_size = prefix_size + 7
                    else:
                        data_size = 0   
                elif groupVal == 13:            # Binary Output Command Events
                    groupName = 'BO_Cmd_Evt'
                    if variationVal == 1:       # Without Time
                        data_size = prefix_size + 1
                    elif variationVal == 2:     # With Time
                        data_size = prefix_size + 7
                    else:
                        data_size = 0  
                array_size_process, count_process, left_to_nextFrag = ReceivedFrame.check_ifAllInSeg(array_size, obj_index, data_size, count)
                bytes_process = byte_data[:(3 if (variationVal==0 and qualifierVal==6) else array_size_process)]
                if obj_index < len(bytes_process):
                    data_readout = ReceivedFrame.read_bioEvt(groupVal, variationVal, bytes_process, obj_index, start_index, prefix_size, count)
                    for data in data_readout:
                        self.application_data[appDataDict]['Object Data'][f'{groupName} {data[0]}'] = data[1] if len(data)==2 else f'val:{data[1]}, time:{data[2]}'
            elif groupVal == 12:                # Binary Output Commands
                groupName = 'BO_Cmd'
                if variationVal == 3:   # Pattern Mask (PCM)
                    quotient, remainder = divmod(count, 4)
                    count_out = quotient+1 if remainder > 0 else quotient
                    data_size = 1
                else:                   # Pattern Control Block (PCB) or Control Relay Output Block (CROB)
                    count_out = count
                    data_size = prefix_size + 11
                array_size_process, count_process, left_to_nextFrag = ReceivedFrame.check_ifAllInSeg(array_size, obj_index, data_size, count_out)
                bytes_process = byte_data[:(3 if (variationVal==0 and qualifierVal==6) else array_size_process)]
                if obj_index < len(bytes_process):
                    data_readout = ReceivedFrame.read_boCmdStatus(groupVal, variationVal, bytes_process, obj_index, start_index, prefix_size, count_process)
                    for data in data_readout:
                        self.application_data[appDataDict]['Object Data'][f'{groupName} {data[0]}'] = data[1]
            elif groupVal in [20, 21, 30, 31, 34, 40]:  # Counters, Analog Input Status, Analog Input Reporting Deadbands, or Analog Output Status
                if groupVal == 30:                      # Analog Input Status
                    groupName = 'AI'
                    if variationVal == 1:               # 32-bit With Flag
                        data_size = prefix_size + 5
                    elif variationVal == 2:             # 16-bit With Flag
                        data_size = prefix_size + 3
                    elif variationVal == 3:             # 32-bit Without Flag
                        data_size = prefix_size + 4
                    elif variationVal == 4:             # 16-bit Without Flag
                        data_size = prefix_size + 2
                    elif variationVal == 5:             # Single-precision, Floating-point With Flag
                        data_size = prefix_size + 5 
                    elif variationVal == 6:             # Double-precision, Floating-point With Flag
                        data_size = prefix_size + 9   
                elif groupVal == 31:                    # Frozen Analog Input
                    groupName = 'Frozen_AI'
                    if variationVal == 1:               # 32-bit With Flag
                        data_size = prefix_size + 5
                    elif variationVal == 2:             # 16-bit With Flag
                        data_size = prefix_size + 3
                    elif variationVal == 3:             # 32-bit With Time-Of-Frozen
                        data_size = prefix_size + 11
                    elif variationVal == 4:             # 16-bit With Time-Of-Frozen
                        data_size = prefix_size + 9
                    elif variationVal == 5:             # 32-bit Without Flag
                        data_size = prefix_size + 4
                    elif variationVal == 6:             # 16-bit Without Flag
                        data_size = prefix_size + 2
                    elif variationVal == 7:             # Single-precision, Floating-point With Flag
                        data_size = prefix_size + 5 
                    elif variationVal == 8:             # Double-precision, Floating-point With Flag
                        data_size = prefix_size + 9
                elif groupVal == 34:                    # Analog Input Reporting Deadbands
                    groupName = 'AI_Deadband'
                    if variationVal == 1:               # 16-bit
                        data_size = prefix_size + 2
                    elif variationVal == 2:             # 32-bit
                        data_size = prefix_size + 4
                    elif variationVal == 3:             # Single-precision, Floating-point
                        data_size = prefix_size + 4
                elif groupVal == 40:                    # Analog Output Status
                    groupName = 'AO'
                    if variationVal == 1:               # 32-bit With Flag
                        data_size = prefix_size + 5
                    elif variationVal == 2:             # 16-bit With Flag
                        data_size = prefix_size + 3
                    elif variationVal == 3:             # Single-precision, Floating-point With Flag
                        data_size = prefix_size + 5 
                    elif variationVal == 4:             # Double-precision, Floating-point With Flag
                        data_size = prefix_size + 9   
                elif groupVal == 20:                    # Counters
                    groupName = 'Counter'
                    if variationVal in [1, 3]:          # 32-bit with Flag, or 32-bit with Flag, Delta
                        data_size = prefix_size + 5
                    elif variationVal in [2, 4]:        # 16-bit with Flag, or 16-bit with Flag, Delta
                        data_size = prefix_size + 3
                    elif variationVal in [5, 7]:        # 32-bit without Flag, or 32-bit without Flag, Delta
                        data_size = prefix_size + 4
                    elif variationVal in [6, 8]:        # 16-bit without Flag, or 16-bit without Flag, Delta
                        data_size = prefix_size + 2    
                elif groupVal == 21:                    # Frozen Counters
                    groupName = 'Frozen_Counter'
                    if variationVal in [1, 3]:          # 32-bit with Flag, or 32-bit with Flag, Delta
                        data_size = prefix_size + 5
                    elif variationVal in [2, 4]:        # 16-bit with Flag, or 16-bit with Flag, Delta
                        data_size = prefix_size + 3
                    elif variationVal in [5, 7]:        # 32-bit with Flag and Time, or 32-bit with Flag and Time, Delta
                        data_size = prefix_size + 11
                    elif variationVal in [6, 8]:        # 16-bit with Flag and Time, or 16-bit with Flag and Time, Delta
                        data_size = prefix_size + 9
                    elif variationVal in [9, 11]:       # 32-bit without Flag, or 32-bit without Flag, Delta
                        data_size = prefix_size + 4
                    elif variationVal in [10, 12]:      # 16-bit without Flag, or 16-bit without Flag, Delta
                        data_size = prefix_size + 2    
                array_size_process, count_process, left_to_nextFrag = ReceivedFrame.check_ifAllInSeg(array_size, obj_index, data_size, count)
                bytes_process = byte_data[:(3 if (variationVal==0 and qualifierVal==6) else array_size_process)]
                if obj_index < len(bytes_process):
                    data_readout = ReceivedFrame.read_aioStatus(groupVal, variationVal, bytes_process, obj_index, start_index, prefix_size, count_process)
                    for data in data_readout:
                        self.application_data[appDataDict]['Object Data'][f'{groupName} {data[0]}'] = data[1]
            elif groupVal in [22, 23, 32, 33, 42, 43]:  # Counters Events, Frozen Counter Events, Analog Input Events, Frozen Analog Input Events, 
                                                        # Analog Output Events, Analog Output Command Events
                if groupVal in [22, 23]:                # Counter Events or Frozen Counter Events
                    groupName = 'Counter_Evt' if groupVal == 22 else 'Frozen_Counter_Evt' 
                    if variationVal in [1, 3]:          # 32-bit With Flag, or 32-bit With Flag, Delta
                        data_size = prefix_size + 5
                    elif variationVal in [2, 4]:        # 16-bit With Flag, or 16-bit With Flag, Delta
                        data_size = prefix_size + 3
                    elif variationVal in [5, 7]:        # 32-bit With Flag and Time, or 32-bit With Flag and Time, Delta
                        data_size = prefix_size + 11
                    elif variationVal in [6, 8]:        # 16-bit Without Flag and Time, or 16-bit With Flag and Time, Delta
                        data_size = prefix_size + 9
                elif groupVal in [32, 33, 42, 43]:      # Analog Events
                    if groupVal == 32:                  # Analog Input Event
                        groupName = 'AI_Evt'            
                    elif groupVal == 33:                # Frozen Analog Input Events
                        groupName = 'Frozen_AI_Evt'     
                    elif groupVal == 42:                # Ananlog Output Events
                        groupName = 'AO_Evt'            
                    elif groupVal == 43:                # Analog Output Command Events
                        groupName == 'Frozen_AO_Evt'
                    if variationVal == 1:               # 32-bit Without Time
                        data_size = prefix_size + 5
                    elif variationVal == 2:             # 16-bit Without Time
                        data_size = prefix_size + 3
                    elif variationVal == 3:             # 32-bit With Time
                        data_size = prefix_size + 11
                    elif variationVal == 4:             # 16-bit With Time
                        data_size = prefix_size + 9
                    elif variationVal == 5:             # Single-precision, Floating-point Without Time
                        data_size = prefix_size + 5
                    elif variationVal == 6:             # Double-precision, Floating-point Without Time
                        data_size = prefix_size + 9
                    elif variationVal == 7:             # Single-precision, Floating-point With Time
                        data_size = prefix_size + 11
                    elif variationVal == 8:             # Double-precision, Floating-point With Time
                        data_size = prefix_size + 15             
                array_size_process, count_process, left_to_nextFrag = ReceivedFrame.check_ifAllInSeg(array_size, obj_index, data_size, count)
                bytes_process = byte_data[:(3 if (variationVal==0 and qualifierVal==6) else array_size_process)]
                if obj_index < len(bytes_process):
                    data_readout = ReceivedFrame.read_aioEvtStatus(groupVal, variationVal, bytes_process, obj_index, start_index, prefix_size, count_process)
                    for data in data_readout:
                        self.application_data[appDataDict]['Object Data'][f'{groupName} {data[0]}'] = data[1]
            elif groupVal == 60:            # Class Objects
                groupName = 'Cls_Obj'
                bytes_process = byte_data[:3]
                left_to_nextFrag = False
                if variationVal in [0, 1, 2, 3]:       # Class 0,1,2,3 data
                    data_readout = [[0, bytes_process[2]==6]]
            # process the object data tuple global value 
            if not isReqFrame:
                new_index_val = data_readout[-1][0] + 1
                is_continue_object, next_index, remainging_count = object_data_tuple_global(oper_mode=Operation_Mode.Get)
                if is_continue_object and (not isNewObject):
                    if remainging_count > len(data_readout):
                        object_data_tuple_global(oper_mode=Operation_Mode.Set, new_val=(True, new_index_val, remainging_count-len(data_readout)))
                    else:
                        object_data_tuple_global(oper_mode=Operation_Mode.Initialize)
                else:
                    if count > len(data_readout):
                        object_data_tuple_global(oper_mode=Operation_Mode.Set, new_val=(True, new_index_val, count-len(data_readout)))
                    else:
                        object_data_tuple_global(oper_mode=Operation_Mode.Initialize)
            if len(byte_data) == len(bytes_process):
                leftover_bytes_val = b''
                break
            elif left_to_nextFrag:
                leftover_bytes_val = byte_data[len(bytes_process):]
                break
            else:
                    byte_data = byte_data[len(bytes_process):]
        if not isReqFrame:
            leftover_bytes_global(oper_mode=Operation_Mode.Set, new_val=byte_data[:obj_index]+leftover_bytes_val)

    @staticmethod
    def _check_error(byte_data):
        start_octet_err = f'{int.from_bytes(byte_data[0:2], "big"):04X}' != '0564'
        data_block_count, expected_total_len = ReceivedFrame.getDataBlockLength(byte_data)
        length_err = len(byte_data) != expected_total_len
        # check CRC for datalink header bytes
        datalink_bytes = byte_data[:10]
        datalink_bytes_crcerr = TransmitFrame.calculateCRC(datalink_bytes[:-2]) != datalink_bytes[-2:]
        # check CRC for each available data byte blocks
        data_bytes_crcerr = False
        if len(byte_data) > 10:
            post_datalink_bytes = byte_data[10:]
            for index in range(data_block_count):
                data_block = post_datalink_bytes[:18]
                data_bytes_crcerr |= TransmitFrame.calculateCRC(data_block[:-2]) != data_block[-2:]
                if len(post_datalink_bytes) > 18:
                    post_datalink_bytes = post_datalink_bytes[18:]
                else:
                    break
        return start_octet_err | length_err | datalink_bytes_crcerr | data_bytes_crcerr
            
    @staticmethod
    def read_bioStatus(groupVal, variationVal, data_bytes, object_index, start_index, prefix_size, count):
        readout = []
        databyte_list = data_bytes[object_index:]
        if groupVal == 3:
            if variationVal == 1:
                for dataVal in databyte_list:
                    databyteBiStr = f'{dataVal:08b}'[::-1]
                    for index in range(4):
                        bi_val = int(databyteBiStr[index*2:index*2+2], 2)
                        if bi_val == 1:
                            bi_val_str = 'DETERMINED_OFF'
                        elif bi_val == 2:
                            bi_val_str = 'DETERMINED_ON'
                        elif bi_val == 3:
                            bi_val_str = 'INDETERMINATE'
                        else:
                            bi_val_str = 'INTERMEDIATE'
                        readout.append([start_index, bi_val_str])
                        start_index += 1
            elif variationVal == 2:
                while True:
                    sub_data_bytes = databyte_list[:(prefix_size+1)]
                    bi_val = int(f'{sub_data_bytes[prefix_size]:08b}'[::-1][6:], 2)
                    if bi_val == 1:
                        bi_val_str = 'DETERMINED_OFF'
                    elif bi_val == 2:
                        bi_val_str = 'DETERMINED_ON'
                    elif bi_val == 3:
                        bi_val_str = 'INDETERMINATE'
                    else:
                        bi_val_str = 'INTERMEDIATE'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, bi_val_str])
                    if len(databyte_list) > (prefix_size+1):
                        databyte_list = databyte_list[(prefix_size+1):]
                    else:
                        break
        else:
            if variationVal == 1:
                for dataByte in databyte_list:
                    bi_val = f'{dataByte:08b}'[::-1]
                    # if (count - start_index) > 8:
                    #     loopVal = 8
                    # elif (count - start_index) < 0:
                    #     loopVal = 1
                    # else:
                    #     loopVal = count - start_index
                    loopVal = min(count, 8)
                    for index in range(loopVal):
                        bi_val_str = 'ON' if bi_val[index] == '1' else 'OFF'
                        readout.append([start_index, bi_val_str])
                        start_index += 1
            elif variationVal == 2:
                while True:
                    sub_data_bytes = databyte_list[:(prefix_size+1)]
                    bi_val = int(f"{sub_data_bytes[prefix_size]:08b}"[::-1][7], 2)
                    if bi_val == 1:
                        bi_val_str = 'ON'
                    else:
                        bi_val_str = 'OFF'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, bi_val_str])
                    if len(databyte_list) > (prefix_size+1):
                        databyte_list = databyte_list[(prefix_size+1):]
                    else:
                        break
        return readout[:count]

    @staticmethod
    def read_bioEvt(groupVal, variationVal, data_bytes, object_index, start_index, prefix_size, count):
        databyte_list = data_bytes[object_index:]
        readout = []
        if groupVal == 2:                   # Binary Input Events
            if variationVal == 1:           # Without Time
                offset = 1
                withTime = False
                time_byte_size = 0
            elif variationVal == 2:         # With Absolute Time
                offset = 7
                withTime = True
                time_byte_size = 6
            elif variationVal == 3:         # With Relative Time
                offset = 3
                withTime = True
                time_byte_size = 2
            while True:
                sub_data_bytes = databyte_list[:(prefix_size+offset)]
                # get binary value
                bi_val = int(f"{sub_data_bytes[prefix_size]:08b}"[::-1][7], 2)
                if bi_val == 1:
                    bi_val_str = 'ON'
                else:
                    bi_val_str = 'OFF'
                # config start_index and data index
                if prefix_size == 1:
                    start_index = 0
                    index_val = sub_data_bytes[0]
                elif prefix_size == 2:
                    start_index = 0
                    index_val = int.from_bytes(sub_data_bytes[2:1]+sub_data_bytes[0:1], 'big')
                else:
                    index_val = start_index
                    start_index += 1
                # get time stamp value if it's available
                if withTime:
                    time_bytes = sub_data_bytes[prefix_size+1:prefix_size+1+time_byte_size]
                    readout.append([index_val, bi_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                else:
                    readout.append([index_val, bi_val_str])
                # check looping condition
                if len(databyte_list) > (prefix_size+offset):
                    databyte_list = databyte_list[(prefix_size+offset):]
                else:
                    break
        elif groupVal == 4:                 # Double-bit Binary Input Events
            if variationVal == 1:           # Without Time
                offset = 1
                withTime = False
                time_byte_size = 0
            elif variationVal == 2:         # With Absolute Time
                offset = 7
                withTime = True
                time_byte_size = 6
            elif variationVal == 3:         # With Relative Time
                offset = 3
                withTime = True
                time_byte_size = 2              
            while True:
                sub_data_bytes = databyte_list[:(prefix_size+offset)]
                bi_val = int(f'{sub_data_bytes[prefix_size]:08b}'[::-1][6:], 2)
                if bi_val == 1:
                    bi_val_str = 'DETERMINED_OFF'
                elif bi_val == 2:
                    bi_val_str = 'DETERMINED_ON'
                elif bi_val == 3:
                    bi_val_str = 'INDETERMINATE'
                else:
                    bi_val_str = 'INTERMEDIATE'
                if prefix_size == 1:
                    start_index = 0
                    index_val = sub_data_bytes[0]
                elif prefix_size == 2:
                    start_index = 0
                    index_val = int.from_bytes(sub_data_bytes[2:1]+sub_data_bytes[0:1], 'big')
                else:
                    index_val = start_index
                    start_index += 1
                # get time stamp value if it's available
                if withTime:
                    time_bytes = sub_data_bytes[prefix_size+1:prefix_size+1+time_byte_size]
                    readout.append([index_val, bi_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                else:
                    readout.append([index_val, bi_val_str])
                # check looping condition
                if len(databyte_list) > (prefix_size+offset):
                    databyte_list = databyte_list[(prefix_size+offset):]
                else:
                    break
        elif groupVal == 11:                 # Binary Output Events
            if variationVal == 1:            # Without Time
                offset = 1
                withTime = False
                time_byte_size = 0
            elif variationVal == 2:          # With Absolute Time
                offset = 7
                withTime = True
                time_byte_size = 6
            while True:
                sub_data_bytes = databyte_list[:(prefix_size+offset)]
                bi_val = int(f"{sub_data_bytes[prefix_size]:08b}"[::-1][7], 2)
                if bi_val == 1:
                    bi_val_str = 'ON'
                else:
                    bi_val_str = 'OFF'
                if prefix_size == 1:
                    start_index = 0
                    index_val = sub_data_bytes[0]
                elif prefix_size == 2:
                    start_index = 0
                    index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                else:
                    index_val = start_index
                    start_index += 1
                # get time stamp value if it's available
                if withTime:
                    time_bytes = sub_data_bytes[prefix_size+1:prefix_size+1+time_byte_size]
                    readout.append([index_val, bi_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                else:
                    readout.append([index_val, bi_val_str])
                # check looping condition
                if len(databyte_list) > (prefix_size+offset):
                    databyte_list = databyte_list[(prefix_size+offset):]
                else:
                    break
        elif groupVal == 13:                 # Binary Output Command Events
            if variationVal == 1:            # Without Time
                offset = 1
                withTime = False
                time_byte_size = 0
            elif variationVal == 2:          # With Absolute Time
                offset = 7
                withTime = True
                time_byte_size = 6
            while True:
                sub_data_bytes = databyte_list[:(prefix_size+offset)]
                bi_val = int(f"{sub_data_bytes[prefix_size]:08b}"[::-1][7], 2)
                ctrl_status_val = int(f"{sub_data_bytes[prefix_size]:08b}"[::-1][:7], 2)
                if bi_val == 1:
                    bi_val_str = f'ON:{Ctrl_Status_Code(ctrl_status_val).name}'
                else:
                    bi_val_str = f'OFF:{Ctrl_Status_Code(ctrl_status_val).name}'
                if prefix_size == 1:
                    start_index = 0
                    index_val = sub_data_bytes[0]
                elif prefix_size == 2:
                    start_index = 0
                    index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                else:
                    index_val = start_index
                    start_index += 1
                # get time stamp value if it's available
                if withTime:
                    time_bytes = sub_data_bytes[prefix_size+1:prefix_size+1+time_byte_size]
                    readout.append([index_val, bi_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                else:
                    readout.append([index_val, bi_val_str])
                # check looping condition
                if len(databyte_list) > (prefix_size+offset):
                    databyte_list = databyte_list[(prefix_size+offset):]
                else:
                    break
        return readout[:count]

    @staticmethod
    def read_boCmdStatus(groupVal, variationVal, data_bytes, object_index, start_index, prefix_size, count):
        databyte_list = data_bytes[object_index:]
        readout = []
        if variationVal == 3:       # Pattern Mask (PCM)
            for dataByte in databyte_list:
                    bi_val = f'{dataByte:08b}'[::-1]
                    for bit_str in bi_val:
                        bi_val_str = 'ON' if bit_str == '1' else 'OFF'
                        readout.append([start_index, bi_val_str])
                        start_index += 1
        elif variationVal in [1, 2]:
            index = 0
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+11)]
                    boCmd_bytes = sub_data_bytes[prefix_size:]
                    bi_val_str = ReceivedFrame.read_crob_pcb(boCmd_bytes, prefix_size)
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, bi_val_str])
                    if len(databyte_list) > (prefix_size+11):
                        databyte_list = databyte_list[(prefix_size+11):]
                    else:
                        break
        return readout[:count]

    @staticmethod
    def read_aioStatus(groupVal, variationVal, data_bytes, object_index, start_index, prefix_size, count):
        databyte_list = data_bytes[object_index:]
        readout = []
        if groupVal == 30:                          # Analog Inputs
            if variationVal in [1, 5]:
                start_offset = 1
                stop_offset = 5
            elif variationVal == 2:
                start_offset = 1
                stop_offset = 3
            elif variationVal == 3:
                start_offset = 0
                stop_offset = 4
            elif variationVal == 4:
                start_offset = 0
                stop_offset = 2
            elif variationVal == 6:
                start_offset = 1
                stop_offset = 9
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if variationVal in [1, 2, 3, 4]:
                        if (prefix_size+start_offset) != 0:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                        else:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1::-1], 'big', signed=True))
                    elif variationVal == 5:
                        aio_val_str = f'{unpack("!f", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset]):.3f}'
                    elif variationVal == 6:
                        aio_val_str = f'{unpack("!d", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset]):.3f}'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, aio_val_str])
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal == 40:                        # Analog Outputs
            if variationVal in [1, 3]:
                start_offset = 1
                stop_offset = 5
            elif variationVal == 2:
                start_offset = 1
                stop_offset = 3
            elif variationVal == 4:
                start_offset = 1
                stop_offset = 9
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if variationVal in [1, 2]:
                        if (prefix_size+start_offset) != 0:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                        else:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1::-1], 'big', signed=True))
                    elif variationVal == 3:
                        aio_val_str = f'{unpack("!f", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset]):.3f}'
                    elif variationVal == 4:
                        aio_val_str = f'{unpack("!d", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset]):.3f}'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, aio_val_str])
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal == 20:                        # Counters
            if variationVal in [1, 3]:
                start_offset = 1
                stop_offset = 5
            elif variationVal in [2, 4]:
                start_offset = 1
                stop_offset = 3
            elif variationVal in [5, 7]:
                start_offset = 0
                stop_offset = 4
            elif variationVal in [6, 8]:
                start_offset = 0
                stop_offset = 2
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if (prefix_size+start_offset) != 0:
                        counter_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                    else:
                        counter_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1::-1], 'big', signed=True))
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, counter_val_str])
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal == 31:                        # Frozen Analog Input
            withTime = False
            time_byte_size = 0
            time_byte_offset = 0
            if variationVal in [1, 7]:
                start_offset = 1
                stop_offset = 5
            elif variationVal == 2:
                start_offset = 1
                stop_offset = 3
            elif variationVal == 3:
                start_offset = 1
                stop_offset = 11
                withTime = True
                time_byte_size = 6
                time_byte_offset = 5
            elif variationVal == 4:
                start_offset = 1
                stop_offset = 9
                withTime = True
                time_byte_size = 6
                time_byte_offset = 3
            elif variationVal == 5:
                start_offset = 0
                stop_offset = 4
            elif variationVal == 6:
                start_offset = 0
                stop_offset = 2
            elif variationVal == 8:
                start_offset = 1
                stop_offset = 9
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if variationVal in [1, 2, 3, 4]:
                        if (prefix_size+start_offset) != 0:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                        else:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1::-1], 'big', signed=True))
                    elif variationVal == 7:
                        aio_val_str = f'{unpack("!f", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset-time_byte_size]):.3f}'
                    elif variationVal == 8:
                        aio_val_str = f'{unpack("!d", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset-time_byte_size]):.3f}'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    # get time stamp value if it's available
                    if withTime:
                        time_bytes = sub_data_bytes[prefix_size+time_byte_offset:prefix_size+time_byte_offset+time_byte_size]
                        readout.append([index_val, aio_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                    else:
                        readout.append([index_val, aio_val_str])
                # check looping condition
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal == 21:                        # Frozen Counters
            withTime = False
            time_byte_size = 0
            time_byte_offset = 0
            if variationVal in [1, 3]:
                start_offset = 1
                stop_offset = 5
            elif variationVal in [2, 4]:
                start_offset = 1
                stop_offset = 3
            elif variationVal in [5, 7]:
                start_offset = 1
                stop_offset = 11
                withTime = True
                time_byte_size = 6
                time_byte_offset = 5
            elif variationVal in [6, 8]:
                start_offset = 1
                stop_offset = 9
                withTime = True
                time_byte_size = 6
                time_byte_offset = 3
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if (prefix_size+start_offset) != 0:
                        counter_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                    else:
                        counter_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1::-1], 'big', signed=True))
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                     # get time stamp value if it's available
                    if withTime:
                        time_bytes = sub_data_bytes[prefix_size+time_byte_offset:prefix_size+time_byte_offset+time_byte_size]
                        readout.append([index_val, counter_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                    else:
                        readout.append([index_val, counter_val_str])
                # check looping condition
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal == 34:                        # Analog Input Reporting Deadbands
            if variationVal == 1:                   # 16-bit
                start_offset = 0
                stop_offset = 2
            elif variationVal in [2, 3]:            # 32-bit or Single-precision Floating-point
                start_offset = 0
                stop_offset = 4
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if variationVal in [1, 2]:
                        if (prefix_size+start_offset) != 0:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                        else:
                            aio_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-1::-1], 'big', signed=True))
                    elif variationVal == 3:
                        aio_val_str = f'{unpack("!f", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset]):.3f}'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    readout.append([index_val, aio_val_str])
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        return readout[:count]    

    @staticmethod
    def read_aioEvtStatus(groupVal, variationVal, data_bytes, object_index, start_index, prefix_size, count):
        databyte_list = data_bytes[object_index:]
        readout = []
        if groupVal in [22, 23]:                    # Counter Events or Frozen Counter Events
            withTime = False
            time_byte_size = 0
            time_byte_offset = 0
            if variationVal in [1, 3]:
                start_offset = 1
                stop_offset = 5
            elif variationVal in [2, 4]:
                start_offset = 1
                stop_offset = 3
            elif variationVal in [5, 7]:
                start_offset = 1
                stop_offset = 11
                withTime = True
                time_byte_size = 6
                time_byte_offset = 5
            elif variationVal in [6, 8]:
                start_offset = 1
                stop_offset = 9
                withTime = True
                time_byte_size = 6
                time_byte_offset = 3
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if (prefix_size+start_offset) != 0:
                        counterEvt_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                    else:
                        counterEvt_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1::-1], 'big', signed=True))
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                     # get time stamp value if it's available
                    if withTime:
                        time_bytes = sub_data_bytes[prefix_size+time_byte_offset:prefix_size+time_byte_offset+time_byte_size]
                        readout.append([index_val, counterEvt_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                    else:
                        readout.append([index_val, counterEvt_val_str])
                # check looping condition
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        elif groupVal in [32, 33, 42, 43]:          # Analog Input, Frozeon Analog Input, Analog Output or Analog Output Command Events
            withTime = False
            time_byte_size = 0
            time_byte_offset = 0
            if variationVal in [1, 5]:
                start_offset = 1
                stop_offset = 5
            elif variationVal == 2:
                start_offset = 1
                stop_offset = 3
            elif variationVal in [3, 7]:
                start_offset = 1
                stop_offset = 11
                withTime = True
                time_byte_size = 6
                time_byte_offset = 5
            elif variationVal == 4:
                start_offset = 1
                stop_offset = 9
                withTime = True
                time_byte_size = 6
                time_byte_offset = 3
            elif variationVal == 6:
                start_offset = 1
                stop_offset = 9
            elif variationVal == 8:
                start_offset = 1
                stop_offset = 15
                withTime = True
                time_byte_size = 6
                time_byte_offset = 9
            while True:
                    sub_data_bytes = databyte_list[:(prefix_size+stop_offset)]
                    if variationVal in [1, 2, 3, 4]:
                        if (prefix_size+start_offset) != 0:
                            aioEvt_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1:prefix_size+start_offset-1:-1], 'big', signed=True))
                        else:
                            aioEvt_val_str = str(int.from_bytes(sub_data_bytes[prefix_size+stop_offset-time_byte_size-1::-1], 'big', signed=True))
                    elif variationVal in [5, 7]:
                        aioEvt_val_str = f'{unpack("!f", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset-time_byte_size]):.3f}'
                    elif variationVal in [6, 8]:
                        aioEvt_val_str = f'{unpack("!d", sub_data_bytes[prefix_size+start_offset:prefix_size+stop_offset-time_byte_size]):.3f}'
                    if groupVal == 43:          # Analog Output Command Events
                        aioEvt_val_str = f'{Ctrl_Status_Code(sub_data_bytes[prefix_size]).name}:{aioEvt_val_str}'
                    if prefix_size == 1:
                        start_index = 0
                        index_val = sub_data_bytes[0]
                    elif prefix_size == 2:
                        start_index = 0
                        index_val = int.from_bytes(sub_data_bytes[1:2]+sub_data_bytes[0:1], 'big')
                    else:
                        index_val = start_index
                        start_index += 1
                    # get time stamp value if it's available
                    if withTime:
                        time_bytes = sub_data_bytes[prefix_size+time_byte_offset:prefix_size+time_byte_offset+time_byte_size]
                        readout.append([index_val, aioEvt_val_str, ReceivedFrame.bytes2timeStr(time_bytes)[0]])
                    else:
                        readout.append([index_val, aioEvt_val_str])
                # check looping condition
                    if len(databyte_list) > (prefix_size+stop_offset):
                        databyte_list = databyte_list[(prefix_size+stop_offset):]
                    else:
                        break
        return readout[:count]

    @staticmethod
    def read_crob_pcb(byte_data, prefix_size):
        first_byte_bits = f'{byte_data[0]:08b}'
        op_type_code_val = int(first_byte_bits[4:], 2)
        tcc_code_val = int(first_byte_bits[:2], 2)
        count_val = byte_data[1]
        on_time_val = ReceivedFrame.bytes2timeStr(byte_data[2:6])[1]
        off_time_val = ReceivedFrame.bytes2timeStr(byte_data[6:10])[1]
        return f'{TCC_Code(tcc_code_val).name},{Op_Type_Code(op_type_code_val).name},Count {count_val},\
On/Off Time {on_time_val}-{off_time_val} msecs,[{Ctrl_Status_Code(byte_data[10]).name}]'

    @staticmethod
    def bytes2timeStr(byte_data):
        dateTimeRef = refTime if len(byte_data) == 2 else datetime(1970, 1, 1)
        bytes_data_array = bytearray(byte_data)
        bytes_data_array.reverse()
        interval_time = 0
        for index in range(len(bytes_data_array)):
            if index == 0:
                interval_time = bytes_data_array[0]
            else:
                interval_time = (interval_time << 8) + bytes_data_array[index]
        new_date_time = dateTimeRef + timedelta(seconds=interval_time/1000)
        new_time_str = new_date_time.strftime('%m/%d/%Y %I:%M:%S.%f %p')
        return (new_time_str[:-6] + new_time_str[-3:], interval_time)

    @staticmethod
    def check_ifAllInSeg(array_size, object_index, data_size, count):
        floorVal = 0
        if data_size != 0:
            floorVal = (array_size - object_index) // data_size
        if floorVal < count:
            return (floorVal*data_size+object_index, floorVal, True)
        else:
            return (data_size*count+object_index, count, False)

    @staticmethod
    def getDataBlockLength(received_data):
        lenVal = received_data[2]
        loopCount = 0
        dlnCount = 5    # octets not counted in Datalink header (05, 64, LEN, & CRC)
        dbnCount = 2    # octets not counted in Data Block (CRC's 2 for each DB)
        dlCount = 5     # the # of countable bytes in Datalink header
        dbCount = 16    # the max # of countable bytes in a Data Block
        minCount = 0x05 # min LEN includes 1 Datalink header & partial data block
        if lenVal > minCount:
            lenTemp = lenVal - dlCount
            while True:
                lenTemp -= dbCount
                loopCount += 1
                if lenTemp < dbCount:
                    break
            if lenTemp > 0:
                loopCount += 1
            return (loopCount, lenVal+dlnCount+loopCount*dbnCount)
        elif lenVal == minCount:
            return (0, lenVal+dlnCount)
        else:
            return (-1, -1)

    @staticmethod
    def getDataBlockBytes(data_bytes, isReqCmd=False):
        '''
        ## The output is a tuple of (dataBlock_bytes, responseInfo_bytes)
        '''
        if len(data_bytes) > 10:
            data_len, __ = ReceivedFrame.getDataBlockLength(data_bytes)
            data_block = data_bytes[10:]
            out_bytes = b''
            fir_bit = (f'{data_block[0]:08b}'[::-1][6] == '1')        # the binary string 0b'' reverses the index order of binary array
            # this following loop is used to remove all CRC bytes
            for _ in range(data_len):
                if len(data_block) >= 18:
                    out_bytes += data_block[:16]
                else:
                    byte_array = bytearray(data_block)
                    # print(byte_array)
                    byte_array.reverse()        # the .reserve() function is in-place, or we could use list slicing as list[::-1] but create a shallow copy, or reseved() function
                                                # but this time it generates an iterator
                    # print(byte_array)
                    sub_reversed_byte_array = byte_array[2:]
                    # print(sub_reversed_byte_array)
                    sub_reversed_byte_array.reverse()
                    # print(sub_reversed_byte_array)
                    # print(bytes(sub_reversed_byte_array))
                    out_bytes += bytes(sub_reversed_byte_array)
                data_block = data_block[18:]
            if fir_bit:     # IR=1, this is the first fragment where App Header should be included
                            # These five octets are Transport Header, Application Control, Function Code, IIN1, IIN2.
                            # They are only useful for the response to enable/disable unsolicited response Request
                if isReqCmd:
                    return (out_bytes[3:], out_bytes[:3])
                else:
                    return (out_bytes[5:], out_bytes[:5])
            else:           # FIR=0, this is not the first fragment where App Header should not be included
                return (out_bytes[1:], out_bytes[:1])
        else:
            return (b'', b'')

    @staticmethod
    def convert2frame(byte_data, isFirstFragment=True, isReqFrame=False):
        try:
            if ReceivedFrame._check_error(byte_data):
                raise FrameError('Error on assemble of received Frame.')
            data_block_bytes, __ = ReceivedFrame.getDataBlockBytes(byte_data, isReqFrame)
            if len(data_block_bytes) > 0:
                return ReceivedFrame(byte_data, isFirstFragment, data_block_bytes, isReqFrame)
            else:
                return ReceivedFrame(byte_data, True, None, isReqFrame)
        except Exception as error:
            raise FrameError('Error while creating DNP frame from received bytes: ' + str(error))

    @staticmethod
    def categorize_receivedBytes(byte_data_list):
        cat_recBytes = {'Msg Readout': byte_data_list, 'Sequence Number': 254, 'Unsolicited Response': False, 
        'Confirmation Required': False, 'Application Ctrl': 0, 'Function Code': 129}
        byte_data = byte_data_list[0]
        data_len = byte_data[2]
        if data_len <= 5:
            if (byte_data[3] & 0b01000000) == 0:    # PRM = 0 indicates a Data Link Layer transaction is being completed by either a master or an outstation outstation
                pass
            else:                                   # PRM = 1 indicates a Data Link Layer transaction is being initiated by either a master or an outstation. Request is
                                                    # from the outstation, DIR=0, PRM=1
                cat_recBytes['Sequence Number'] = 253
                cat_recBytes['Function Code'] = byte_data[3] & 0b00001111
        else:
            control_val = byte_data[11]
            seq_val = int(f'{control_val:08b}'[4:], 2)
            control_bits = f'{control_val:08b}'[:4][::-1]
            cat_recBytes['Sequence Number'] = seq_val
            cat_recBytes['Unsolicited Response'] = control_bits[0] == '1'
            cat_recBytes['Confirmation Required'] = control_bits[1] == '1'
            cat_recBytes['Application Ctrl'] = control_val
            cat_recBytes['Function Code'] = byte_data[12]
            cat_recBytes['IINs'] = [int.from_bytes(byte_data[13:14], 'big'), int.from_bytes(byte_data[14:15], 'big')]
        return cat_recBytes

class FrameError(BaseException):
    pass

if __name__ == '__main__':
    # address = (52, 0)
    # #obj_def = {'Function Codes': Function_Code.READ, 'Object Info': [{'Object': '01', 'Variation': '01', 'Qualifier': '00', 'Range': '0000'}]}
    # init_all()
    # prmFunCode, obj_def = TransmitFrame.dnpReq_generation(DNP_Request.Issue_DNP_Command, op_params=DNP_Command.Class_1_2_3_0_Data)
    # appl_ctrl = TransmitFrame.getApplCtrl(obj_def)
    # datalink_ctrl = TransmitFrame.getDataLinkReqCtrl(prmFunCode)
    # req_frame = TransmitFrame(address, appl_ctrl, datalink_ctrl, obj_def)
    # # dnp_frame_2 = CommonFrame(address, appl_ctrl, datalink_ctrl, obj_def)
    # #dnp_frame_2 = CommonFrame(address, appl_ctrl, datalink_ctrl, obj_def)
    # print(req_frame.convert2bytes())
    # print(binascii.hexlify(req_frame.convert2bytes()))
    # print(binascii.hexlify(dnp_frame_2.byte_string))
    #0564 0DC4 3400 0000 8654 C2C2 0101 0100 0000 1783
    #0564 0dc4 3400 0000 8654 c2c2 0101 0100 0000 1783
    #0564 0dc4 3400 0000 8654 c0c0 0101 0100 0000 f711   
    #print(dnp_frame_2.byte_string)
    first_bytes = b'0564ff4400003400084640e1810000020217338a81bce2f86c80fce0010a017cf6f86c80010e817cf6f86c802a75010001aef6f86\
c80010181aef6f86c808265010201f4f6f86c80010381f4f6f86c80c85b0104013bf7f86c800105813bf7f86c80a89201060163f7f86c8001078163f7f86c\
809854010e0134fff86c80010a8134fff86c80ce6b0100817e81f96c800101017e81f96c8050300102817e81f96c800103017e81f96c80a4520104817e81f\
96c800105017e81f96c80b8f50107019981f96c800106819981f96c80089101168108dff96c8001128108dff96c80fb21010a0109dff96c8001108109dff9\
6c809e3b011601e534fa6c80011201e534fa6c8078d0011001e734fa6c80010a81e734fa6c808eb2010a01afc9fa6c80010e60b0'
    second_bytes = b'0564ff440000340008460181b0c9fa6c80010001e3c9fa6c800120070181e3c9fa6c8001020126cafa6c8001ce90038126cafa6c\
800104016dcafa6c80013b9705816dcafa6c8001060196cafa6c8001ba7f078196cafa6c80010e0168d2fa6c800128b70a8168d2fa6c80010081c64afb6c8\
001b8b90101c64afb6c80010281c64afb6c80015af70301c64afb6c80010481c64afb6c80012e180501c64afb6c80010701e04afb6c80015da40681e04afb\
6c80010a01e540fc6c8001eb590b814d41fc6c800101010000a055080029a4110040000000000080821800001004046e4700001e0200004b010f00010c000\
10d00a45a011c00010b0001110001ec5e01000001890e07000103000103000103000109000100f5db00010000010000010000618d'
    # byte_data_list = []
    # byte_data_list.append(first_bytes)
    # byte_data_list.append(second_bytes)
    # for index in range(len(byte_data_list)):
    #     byte_data = binascii.unhexlify(byte_data_list[index])
    # # print(binascii.hexlify(byte_data))
    #     received_frame = ReceivedFrame.convert2frame(byte_data, isFirstFragment=index==0)
    #     print(received_frame.__dict__)
    # x, y = ReceivedFrame.getDataBlockBytes(byte_data)
    # print(binascii.hexlify(x))
    # print(binascii.hexlify(y))
    another_bytes = b'\x05dND\x00\x004\x00/k\xc0\xf9\x82\x00\x00\x02\x02\x17\x08\x00\x81>\x08(m\x80dZ\x01\x01\x01>\x08(m\x80\x01\
\x02\x81>\x08(m\x80\xdfw\x01\x03\x01>\x08(m\x80\x01\x04\x81>\x08(m\x80\xda%\x01\x05\x01>\x08(m\x80\x01\x07\x01V\x08(m\x80x\x81\
\x01\x06\x81V\x08(m\x80\x01F\x1b'
    # req_bytes = binascii.unhexlify(b'05640bc4340000005f3fc0c0010100065b7f')
    # req_bytes =   binascii.unhexlify(b'056411c434000000f5fbc2c2143c02063c03063c0406d32f')
    req_bytes = binascii.unhexlify(b'05640bc4340000005f3fc2c2010b000650e1')
    confirm_bytes = b'\x05d\x08\xc44\x00\x00\x00\x0f\xac\xc6\xd2\x00n\x07'
    rec_bytes = b'\x05d\x1eD\x00\x004\x00\x93\xbd\xc0\xf1\x82\x00\x00\x02\x02\x17\x02\n\x01\xafk\xe4\xb5\x80\x96:\x01\x0c\x81\x17l\xe4\xb5\x80\x01\xd0\xd9'
    # print(binascii.hexlify(rec_bytes))
    # print(req_bytes)
    # print(binascii.hexlify(req_bytes))
    # print(ReceivedFrame.convert2frame(req_bytes, isReqFrame=True).__dict__)
    # cat_Result = ReceivedFrame.categorize_receivedBytes([another_bytes])
    # print(cat_Result)
    # receved_bytes = [binascii.unhexlify(b'05641e440000340093bdc0f1820000020217020a01af6be4b580963a010c81176ce4b58001d0d9')]
    # print(ReceivedFrame.convert2frame(receved_bytes[0], isReqFrame=False).__dict__)
    # print(ReceivedFrame.categorize_receivedBytes(receved_bytes))
    bytes_from_test = b'05647dc4fcff98ffd15bc7c701\
    66010404020402\
    6601047a2e7a74892e\
    66010400800b80\
    66010400812181\
    662c96010450815181\
    66010400c005c0\
    6601046567eec0efc0\
    66010400c105c1\
    66010417c1d58617c1\
    66010440c143c1\
    66010451c151c1e445\
    66010400c213c2\
    660105008f0400018fec7f0400\
    6601051600060025000600\
    660105c45a3c000600470006003ef4'
    recv_bytes = binascii.unhexlify(b'0564104400003400964cc0c28100000101000308159d35')
    print(ReceivedFrame.convert2frame(recv_bytes, isReqFrame=False).__dict__)