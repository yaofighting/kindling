package detect

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestXxx(t *testing.T) {

	respStr := `{"tasks":[{"taskId":123,"taskName":"","reportCode":"","batchCode":"","taskType":0,"destinationType":0,"serviceAddress":"","protocol":0,"requestParams":"","requestMethod":"","conflictType":0}]}`

	ap := &AvailabilityDetectReponse{}

	err := json.Unmarshal([]byte(respStr), ap)

	fmt.Printf("1 %+v, %v\n", ap, err)

	ap2 := &AvailabilityDetectReponse{
		Tasks: []TaskVO{
			{TaskId: 123},
		},
	}

	data, err := json.Marshal(ap2)

	fmt.Printf("2 %+v, %v\n", string(data), err)

}
