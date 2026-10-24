# 编译 C 扫描器、设置抓包权限、启动 Flask 前端
#
# 常用命令：
#   make          编译并确保 main 有抓包权限
#   make run      编译 + 授权 + 启动 app.py
#   make start    同 make run
#   make clean    清理编译产物

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDLIBS   = -lnet -lpcap
PYTHON  ?= python3
SUDO    ?= sudo

CAPS     = cap_net_raw,cap_net_admin

SRCS     = main.c send.c sniff.c
OBJS     = $(SRCS:.c=.o)

.DEFAULT_GOAL := all
.PHONY: all cap run start clean help

# 默认目标：编译 + 设置抓包权限
all: main cap

main: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

main.o: main.c send.h sniff.h
	$(CC) $(CFLAGS) -c main.c -o $@

send.o: send.c send.h
	$(CC) $(CFLAGS) -c send.c -o $@

sniff.o: sniff.c sniff.h
	$(CC) $(CFLAGS) -c sniff.c -o $@

# 给 main 设置抓包能力；已有能力时不会重复 sudo
cap: main
	@if getcap ./main 2>/dev/null | grep -q 'cap_net_raw'; then \
		echo "main 已有抓包权限"; \
	else \
		echo "为 main 设置抓包权限..."; \
		$(SUDO) setcap $(CAPS)=eip ./main; \
	fi
	@getcap ./main

run: all
	$(PYTHON) app.py

start: run

clean:
	rm -f $(OBJS) main

help:
	@echo "make        编译并设置抓包权限"
	@echo "make run    编译、授权并启动 app.py"
	@echo "make start  同 make run"
	@echo "make clean  清理 main 和 .o 文件"
