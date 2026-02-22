module github.com/nextron-systems/thunderstorm-stub-server

go 1.21

// Optional YARA support:
//   go get github.com/hillu/go-yara/v4
//   go build -tags yara
//   go test  -tags yara ./...
//
// Requires libyara >= 4.x installed (brew install yara  /  apt install libyara-dev)
