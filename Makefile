# 用法
# make build dir=file_monitor
# make clean dir=file_monitor
dir = file_monitor

build: clean
	cd ${dir}; go generate; go build

clean:
	rm -rf ${dir}/*.o; rm -rf ${dir}/bpf_*.go; rm -rf ${dir}/${dir}