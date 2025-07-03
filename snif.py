# AGPL License

# Copyright (c) 2024 Tony Gorez

import lldb
import json

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f snif.set_xpc_breakpoints snif')
    print("XPC Tracker plugin loaded. Use 'snif' to set breakpoints on XPC functions.")

def execute_command(command):
    interpreter = lldb.debugger.GetCommandInterpreter()
    result = lldb.SBCommandReturnObject()
    interpreter.HandleCommand(command, result)
    if result.Succeeded():
        return result.GetOutput().strip()
    else:
        return result.GetError()

def safely_evaluate_expression(frame, expression) -> lldb.SBValue:
    opts = lldb.SBExpressionOptions()
    opts.SetLanguage(lldb.eLanguageTypeObjC)
    opts.SetIgnoreBreakpoints(True)
    result = frame.EvaluateExpression(expression, opts)
    return result

def serialize_xpc_message(frame, xpc_dict):

    objc_code = f'''
    @import Foundation;

    typedef void* xpc_object_t;
    typedef const struct _xpc_type_s * xpc_type_t;

    extern xpc_type_t xpc_get_type(xpc_object_t object);
    extern const char *xpc_string_get_string_ptr(xpc_object_t xstring);
    extern int64_t xpc_int64_get_value(xpc_object_t xint);
    extern uint64_t xpc_uint64_get_value(xpc_object_t xuint);
    extern double xpc_double_get_value(xpc_object_t xdouble);
    extern bool xpc_bool_get_value(xpc_object_t xbool);
    extern const void *xpc_data_get_bytes_ptr(xpc_object_t xdata);
    extern size_t xpc_data_get_length(xpc_object_t xdata);
    extern bool xpc_dictionary_apply(xpc_object_t xdict, bool (^applier)(const char *key, xpc_object_t value));
    extern const char *xpc_copy_description(xpc_object_t object);

    extern const struct _xpc_type_s _xpc_type_string;
    extern const struct _xpc_type_s _xpc_type_int64;
    extern const struct _xpc_type_s _xpc_type_uint64;
    extern const struct _xpc_type_s _xpc_type_bool;
    extern const struct _xpc_type_s _xpc_type_double;
    extern const struct _xpc_type_s _xpc_type_data;
    extern const struct _xpc_type_s _xpc_type_array;

    #define XPC_TYPE_STRING (&_xpc_type_string)
    #define XPC_TYPE_INT64 (&_xpc_type_int64)
    #define XPC_TYPE_UINT64 (&_xpc_type_uint64)
    #define XPC_TYPE_BOOL (&_xpc_type_bool)
    #define XPC_TYPE_DOUBLE (&_xpc_type_double)
    #define XPC_TYPE_DATA (&_xpc_type_data)
    #define XPC_TYPE_ARRAY (&_xpc_type_array)

    // TODO: we should handle the case where the root type is not a dictionary
    id (^serialize_xpc_message)(xpc_object_t) = ^id(xpc_object_t xpc_obj) {{
        NSMutableDictionary *result = [NSMutableDictionary dictionary];
        xpc_dictionary_apply((xpc_object_t)xpc_obj, ^bool(const char *key, xpc_object_t value) {{
            NSString *keyStr = [NSString stringWithCString:key encoding:NSUTF8StringEncoding];
            xpc_type_t type = xpc_get_type(value);

            if (type == XPC_TYPE_STRING) {{
                result[keyStr] = [NSString stringWithCString:xpc_string_get_string_ptr(value) encoding:NSUTF8StringEncoding];
            }} else if (type == XPC_TYPE_INT64) {{
                result[keyStr] = @(xpc_int64_get_value(value));
            }} else if (type == XPC_TYPE_UINT64) {{
                result[keyStr] = @(xpc_uint64_get_value(value));
            }} else if (type == XPC_TYPE_BOOL) {{
                result[keyStr] = @(xpc_bool_get_value(value));
            }} else if (type == XPC_TYPE_DOUBLE) {{
                result[keyStr] = @(xpc_double_get_value(value));
            }} else if (type == XPC_TYPE_DATA) {{
                NSData *data = [NSData dataWithBytes:xpc_data_get_bytes_ptr(value) length:xpc_data_get_length(value)];
                result[keyStr] = [data base64EncodedStringWithOptions:0];
            }} else if (type == XPC_TYPE_ARRAY) {{
                // TODO: Implement array serialization
                // Find a way to call recursively serialize_xpc_message with value
                result[keyStr] = @(xpc_copy_description(value));
            }} else {{
                result[keyStr] = @"Unknown type";
            }}

            return true;
        }});

        return result;
    }};

    id result = serialize_xpc_message(xpc_object_t({xpc_dict}));

    NSError *error = nil;
    NSData *jsonData = [NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingPrettyPrinted error:&error];
    error ? [error localizedDescription] : [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding]
    '''

    # Evaluate the Objective-C code in the current frame
    result = safely_evaluate_expression(frame, objc_code)

    print(result)

    if not result:
        return {"error": {"message": "Failed to evaluate XPC serialization code", "data": ""}}
    if result.GetError().Fail():
        return {"error": {"message": result.GetError().GetCString(), "data": ""}}
    result = result.GetValue()
    if not result:
        return {"error": {"message": "No result from XPC serialization", "data": ""}}
    if result.startswith("error:"):
        return {"error": {"message": result, "data": ""}}

    # Parse the JSON string
    try:
        json_obj = json.loads(result)
        return json_obj
    except json.JSONDecodeError as e:
        return {"error": {"message": str(e), "data": result}}

def capture_xpc_event(frame, direction):

    xpc_func = frame.GetFunctionName()
    conn = frame.FindRegister("x0").GetValue()
    msg = frame.FindRegister("x1").GetValue()

    # Get connection name
    get_connection_name_expr = f'''
    @import Foundation;
    typedef NSObject<OS_xpc_object> * xpc_connection_t;
    extern const char * xpc_connection_get_name(xpc_connection_t connection);

    xpc_connection_t conn = (xpc_connection_t){conn};
    const char *name = xpc_connection_get_name(conn);
    name ? [NSString stringWithUTF8String:name] : @"<null>";
    '''

    # Safely evaluate the expression to get the connection name
    connection_name = safely_evaluate_expression(frame, get_connection_name_expr)
    if connection_name and connection_name.GetError().Success():
        connection_name = connection_name.GetSummary()
        if connection_name and connection_name.startswith('"') and connection_name.endswith('"'):
            connection_name = connection_name[1:-1]  # Remove quotes
    else:
        connection_name = None
        if connection_name:
            print(f"Error getting connection name: {connection_name.GetError().GetCString()}")
    if connection_name is None:
        connection_name = "Unknown"
    elif connection_name == "<null>":
        connection_name = "None"


    # Get connection pid
    get_connection_pid_expr = f'''
    @import Foundation;
    typedef NSObject<OS_xpc_object> * xpc_connection_t;
    extern pid_t xpc_connection_get_pid(xpc_connection_t connection);

    xpc_connection_t conn = (xpc_connection_t){conn};
    (int)xpc_connection_get_pid(conn);
    '''

    # Safely evaluate the expression to get the connection PID
    connection_pid = safely_evaluate_expression(frame, get_connection_pid_expr)
    if connection_pid and connection_pid.GetError().Success():
        connection_pid = connection_pid.GetValueAsSigned()
    else:
        connection_pid = None
        if connection_pid:
            print(f"Error getting connection PID: {connection_pid.GetError().GetCString()}")
    if connection_pid is None:
        connection_pid = "Unknown"
    elif connection_pid == 0:
        connection_pid = "Self"
    else:
        connection_pid = str(connection_pid)

    # Serialize the XPC message
    message = serialize_xpc_message(frame, msg)

    # print json object with all details
    xpc_data = {
        "xpc_function": xpc_func,
        "connection_name": connection_name,
        "connection_pid": connection_pid,
        "message": message,
        "direction": direction,
    }

    return json.dumps(xpc_data, indent=4)


def send_callback(frame, bp_loc, internal_dict):
    bp = bp_loc.GetBreakpoint()
    bp.SetEnabled(False)
    process = frame.GetThread().GetProcess()
    xpc_event = capture_xpc_event(frame, "send")
    # process.Continue()

    print(xpc_event)
    return False

def recv_callback(frame, bp_loc, internal_dict):
    bp = bp_loc.GetBreakpoint()
    # bp.SetEnabled(False)
    process = frame.GetThread().GetProcess()
    xpc_event = capture_xpc_event(frame, "recv")
    # process.Continue()

    print(xpc_event)

    return False

def set_xpc_breakpoints(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()

    xpc_send_functions = [
        'xpc_connection_send_message',
        'xpc_connection_send_message_with_reply',
        'xpc_connection_send_message_with_reply_sync',
    ]
    for func in xpc_send_functions:
        breakpoint = target.BreakpointCreateByName(func)
        breakpoint.SetScriptCallbackFunction('snif.send_callback')
        breakpoint.SetAutoContinue(True)
        print(f"Set breakpoint on: {func}")

    xpc_recv_functions = [
        'xpc_connection_set_event_handler',
        'xpc_connection_set_event_handler_with_flags',
    ]
    for func in xpc_recv_functions:
        breakpoint = target.BreakpointCreateByName(func)
        breakpoint.SetScriptCallbackFunction('snif.recv_callback')
        breakpoint.SetAutoContinue(True)
        print(f"Set breakpoint on: {func}")

    result.PutCString("Breakpoints set on XPC functions.")
    result.SetStatus(lldb.eReturnStatusSuccessFinishResult)
