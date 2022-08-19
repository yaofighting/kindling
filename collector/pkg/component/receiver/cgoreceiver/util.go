package cgoreceiver

import "C"

func MakeParamsListForSlowSyscall(params map[string]string) ([]CEventParamsForSubscribe, bool) {
	var paramsList []CEventParamsForSubscribe
	var ok bool
	var val string
	var temp CEventParamsForSubscribe
	val, ok = params["latency"]
	if !ok {
		return paramsList, false
	}
	temp.name = C.CString("latency")
	temp.value = C.CString(val)
	paramsList = append(paramsList, temp)

	val, ok = params["timeout"]
	if !ok {
		return paramsList, false
	}
	temp.name = C.CString("timeout")
	temp.value = C.CString(val)
	paramsList = append(paramsList, temp)

	return paramsList, true
}

func MakeParamsListForErrorSyscall(params map[string]string) []CEventParamsForSubscribe {
	var paramsList []CEventParamsForSubscribe
	var temp CEventParamsForSubscribe
	for key, syscallname := range params {
		temp.name = C.CString(key)
		temp.value = C.CString(syscallname)
		paramsList = append(paramsList, temp)
	}
	return paramsList
}
