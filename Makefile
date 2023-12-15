PROJECT = icmptunnel
SOURCE = icmptunnel.c

CC = gcc
CFLAGS = -Wall
LDFLAGS = -lz

SERVER = example.com
DEPLOY_PATH = /home/alex/$(PROJECT)

default: $(PROJECT)

$(PROJECT): $(SOURCE)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

clean:
	rm $(PROJECT)

# Deploy
d: $(PROJECT)
	scp $(PROJECT) $(SERVER):$(DEPLOY_PATH)/$(PROJECT)

# Run client
c: $(PROJECT)
	sudo ./$(PROJECT) -c $(SERVER) -d -a 10.20.30.2 -i eth0

# Run server
s: $(PROJECT)
	sudo ./$(PROJECT) -sd -i eth0 -a 10.20.30.1
