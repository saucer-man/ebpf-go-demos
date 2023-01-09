# 用法
# make build dir=open_monitor
# make clean dir=open_monitor
dir = open_monitor

build: clean
	cd ${dir}; go generate; go build

clean:
	rm -rf ${dir}/*.o; rm -rf ${dir}/bpf_*.go; rm -rf ${dir}/${dir}