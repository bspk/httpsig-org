#!/bin/bash

docker build . -t httpsig-org && \
	docker run --rm -it --name httpsig-org -p 8000:8000 httpsig-org
