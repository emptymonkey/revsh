
KEY_BITS = 2048

OPENSSL = /usr/bin/openssl

CC = /usr/bin/cc

#CFLAGS = -Wall -Wextra -std=c99 -pedantic -Os -DFREEBSD
CFLAGS = -Wall -Wextra -std=c99 -pedantic -Os

LIBS = -lssl -lcrypto

OBJS = revsh_io.o string_to_vector.o broker.o

KEYS_DIR = keys


all: revsh

revsh: revsh.c remote_io_helper.h common.h config.h $(OBJS) in_the_key_of_c
	if [ ! -e $(KEYS_DIR) ]; then \
		mkdir $(KEYS_DIR) ; \
	fi
	if [ ! -e $(KEYS_DIR)/dh_params.c ]; then \
    $(OPENSSL) dhparam -C $(KEY_BITS) -noout >$(KEYS_DIR)/dh_params.c ; \
		echo "DH *(*get_dh)() = &get_dh$(KEY_BITS);" >>$(KEYS_DIR)/dh_params.c ; \
  fi
	if [ ! -e $(KEYS_DIR)/controller_key.pem ]; then \
		$(OPENSSL) req -batch -newkey rsa:$(KEY_BITS) -nodes -x509 -days 36500 -keyout $(KEYS_DIR)/controller_key.pem -out $(KEYS_DIR)/controller_cert.pem ; \
	fi
	if [ ! -e $(KEYS_DIR)/target_key.pem ]; then \
    $(OPENSSL) req -batch -newkey rsa:$(KEY_BITS) -nodes -x509 -days 36500 -keyout $(KEYS_DIR)/target_key.pem -out $(KEYS_DIR)/target_cert.pem ; \
	fi
	if [ ! -e $(KEYS_DIR)/controller_fingerprint.c ]; then \
		./in_the_key_of_c -c $(KEYS_DIR)/controller_cert.pem -f >$(KEYS_DIR)/controller_fingerprint.c ; \
	fi
	if [ ! -e $(KEYS_DIR)/target_key.c ]; then \
		./in_the_key_of_c -k $(KEYS_DIR)/target_key.pem >$(KEYS_DIR)/target_key.c ; \
	fi
	if [ ! -e $(KEYS_DIR)/target_cert.c ]; then \
		./in_the_key_of_c -c $(KEYS_DIR)/target_cert.pem >$(KEYS_DIR)/target_cert.c ; \
	fi
	$(CC) $(LIBS) $(CFLAGS) $(OBJS) -o revsh revsh.c

revsh_io: revsh_io.c remote_io_helper.h common.h config.h
	$(CC) $(LIBS) $(CFLAGS) -c -o revsh_io.o revsh_io.c

string_to_vector: string_to_vector.c string_to_vector.h common.h config.h
	$(CC) $(CFLAGS) -c -o string_to_vector.o string_to_vector.c

broker: broker.c common.h config.h
	$(CC) $(CFLAGS) -c -o broker.o broker.c

in_the_key_of_c: in_the_key_of_c.c
	$(CC) $(LIBS) $(CFLAGS) -o in_the_key_of_c in_the_key_of_c.c


install:
	if [ ! -e $(HOME)/.revsh ]; then \
		mkdir $(HOME)/.revsh ; \
	fi
	if [ -e $(HOME)/.revsh/$(KEYS_DIR) ]; then \
		echo "\nERROR: $(HOME)/.revsh/$(KEYS_DIR) already exists! Move it safely out of the way then try again, please." ; \
	else \
		cp -r $(KEYS_DIR) $(HOME)/.revsh ; \
		cp revsh $(HOME)/.revsh/$(KEYS_DIR) ; \
		if [ ! -e $(HOME)/.revsh/revsh ]; then \
			ln -s $(HOME)/.revsh/$(KEYS_DIR)/revsh $(HOME)/.revsh/revsh ; \
		fi \
	fi

# make clean will remove everything. Because dh_params_*.c will take awhile to recreate, I've added
# a make dirty line which will remove everything except the dh_params_*.c file. This was quite useful
# during dev. This makes a rebuild with new key / cert pairs go pretty quick.
dirty:
	rm revsh in_the_key_of_c $(KEYS_DIR)/target* $(KEYS_DIR)/controller* $(OBJS)

clean:
	rm revsh in_the_key_of_c $(KEYS_DIR)/* $(OBJS)
	rmdir $(KEYS_DIR)
