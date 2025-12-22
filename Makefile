.PHONY: setup start stop test logs clean restart

IMAGE_NAME = stun-server
CONTAINER_NAME = stun-server

setup:
	docker build -t $(IMAGE_NAME) .

start:
	docker run -d \
		-p 3478:3478/udp \
		--name $(CONTAINER_NAME) \
		-e STUN_BIND_ADDRESS=0.0.0.0:3478 \
		-e STUN_BUFFER_SIZE=2048 \
		$(IMAGE_NAME)
	@echo "STUN server started on port 3478/udp"

stop:
	docker stop $(CONTAINER_NAME) || true
	docker rm $(CONTAINER_NAME) || true

test:
	cargo test

clean: stop
	docker rmi $(IMAGE_NAME) || true

restart: stop start