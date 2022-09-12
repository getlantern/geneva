
test-and-cover:
	@TP=$$(go list ./...) && \
	CP=$$(echo $$TP | tr ' ', ',') && \
	set -x && \
	GO111MODULE=on go test -json -race -failfast -covermode=atomic -coverprofile=profile.cov -coverpkg "$$CP" $$TP
