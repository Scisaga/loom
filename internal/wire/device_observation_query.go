package wire

import "errors"

const LocalDeviceObservationsPath = "/internal/device-observations"
const DeviceObservationCASecretIDV1 = "server-observation-ca"

// 只在 root-only Unix socket 交换；服务器集合由 control 的当前 Device 配置投影。
type DeviceObservationQueryV1 struct {
	Schema  int      `json:"schema"`
	Servers []string `json:"servers"`
}

func ValidateDeviceObservationQuery(query *DeviceObservationQueryV1) error {
	if query == nil || query.Schema != 1 || query.Servers == nil || len(query.Servers) > 256 {
		return errors.New("[服务器观测] 请求集合无效")
	}
	for i, id := range query.Servers {
		if !validIdentifier(id, 128) || i > 0 && query.Servers[i-1] >= id {
			return errors.New("[服务器观测] 节点集合必须排序、唯一")
		}
	}
	return nil
}
