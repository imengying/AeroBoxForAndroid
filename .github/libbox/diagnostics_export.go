package libbox

import (
	"encoding/json"
	"sort"

	"github.com/gofrs/uuid/v5"
)

type diagnosticConnection struct {
	ID          string `json:"id"`
	Network     string `json:"network"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Domain      string `json:"domain"`
	Process     string `json:"process"`
	Rule        string `json:"rule"`
	Outbound    string `json:"outbound"`
	CreatedAt   int64  `json:"createdAt"`
	Upload      int64  `json:"upload"`
	Download    int64  `json:"download"`
}

// ConnectionSnapshot enables tracking for new connections without a control socket.
// Call StopConnectionTracking when the diagnostics view is no longer visible.
func (s *CommandServer) ConnectionSnapshot() (string, error) {
	instance := s.StartedService.Instance()
	if instance == nil || instance.TrafficManager() == nil {
		return "[]", nil
	}
	manager := instance.TrafficManager()
	manager.SetTrackingEnabled(true)
	connections := manager.Connections()
	sort.Slice(connections, func(i, j int) bool { return connections[i].CreatedAt.After(connections[j].CreatedAt) })
	if len(connections) > 500 {
		connections = connections[:500]
	}
	result := make([]diagnosticConnection, 0, len(connections))
	for _, connection := range connections {
		metadata := connection.Metadata
		item := diagnosticConnection{
			ID: connection.ID.String(), Network: metadata.Network,
			Source: metadata.Source.String(), Destination: metadata.Destination.String(),
			Domain: metadata.Domain, Outbound: connection.Outbound,
			CreatedAt: connection.CreatedAt.UnixMilli(),
			Upload:    connection.Upload.Load(), Download: connection.Download.Load(),
		}
		if connection.Rule != nil {
			item.Rule = connection.Rule.String()
		}
		if info := metadata.ProcessInfo; info != nil {
			if len(info.AndroidPackageNames) > 0 {
				item.Process = info.AndroidPackageNames[0]
			}
		}
		result = append(result, item)
	}
	content, err := json.Marshal(result)
	return string(content), err
}

func (s *CommandServer) StopConnectionTracking() {
	instance := s.StartedService.Instance()
	if instance != nil && instance.TrafficManager() != nil {
		instance.TrafficManager().SetTrackingEnabled(false)
	}
}

func (s *CommandServer) CloseTrackedConnection(id string) error {
	parsed, err := uuid.FromString(id)
	if err != nil {
		return err
	}
	instance := s.StartedService.Instance()
	if instance != nil && instance.TrafficManager() != nil {
		if connection := instance.TrafficManager().Connection(parsed); connection != nil {
			return connection.Close()
		}
	}
	return nil
}
