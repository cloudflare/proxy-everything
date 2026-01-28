build:
	docker build -t proxy-everything:dev .

CONTAINER=test-container
run: build
	docker run \
		--add-host=host.docker.internal:host-gateway \
		-d --name $(CONTAINER) ubuntu:latest sleep infinity

	docker run \
		-it --rm --cap-add=NET_ADMIN \
		--network container:$(CONTAINER) \
		--name $(CONTAINER)-proxy proxy-everything:dev
