// +build windows

package docker

type Watcher struct{}

func New() (*Watcher, error) {
	return nil, ErrorNotImplementedForOS
}

func (_ *Watcher) ListContainers() (map[string]interface{}, error) {
	return nil, ErrorNotImplementedForOS
}

func (_ *Watcher) ContainerNameByID(_ string) (string, error) {
	return "", ErrorNotImplementedForOS
}
