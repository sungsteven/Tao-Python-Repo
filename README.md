# Tao-Python-Repo
This is a collection of Python projects that I have developed
Project of DNP3-Master-Simulator
***This simulates a SCADA master that could be used to test communications to a DNP3 outstation
***The following features are available as of now
***1. read/write Binary I/O, Analog I/O, read counters
***2. issue DNP commands
****Enable_Unsolicited_Response = 0
    Disable_Unsolicited_Response = 1
    Class_1_2_3_0_Data = 2
    Class_1_Data = 3
    Class_2_Data = 4
    Class_3_Data = 5
    Class_0_Data = 6
    Link_Status = 7
    Reset_Link = 8
    Device_Attributes = 9
    Binary_Input_Status = 10
    Binary_Input_Change = 11
    Binary_Input_Changes_and_Current_States = 12
    Binary_Output_Status = 13
    Binary_Output_Event = 14
    Binary_Output_Command_Event = 15
    Binary_Counter = 16
    Frozen_Counter = 17
    Binary_Counter_Change = 18
    Frozen_Counter_Change = 19
    Analog_Input_Status = 20
    Frozen_Analog_Input = 21
    Analog_Change_Event = 22
    Frozen_Analog_Event = 23
    Analog_Output_Status = 24
    Analog_Output_Event = 25
    Analog_Output_Command_Event = 26
    Read_Analog_Deadbands = 27
    Security_Statistics = 28
    Security_Statistics_Events = 29
    Time_Synchronization = 30
    Clear_Restart = 31
    Warm_Restart = 32
    Cold_Restart = 33
***3. capture unsolicited response
