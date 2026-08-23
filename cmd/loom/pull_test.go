package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 慢不是故障。旧实现给二进制套的是 60 秒**总时长**上限,于是一个一直在走、
// 只是走得慢的下载会被砍掉 —— edge-a 就是这么失败的。
func TestGetBlobSurvivesSlowButProgressing(t *testing.T) {
	want := bytes.Repeat([]byte("x"), 8000)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		// 分 8 段发,每段之间歇一会儿。总时长远超单次停顿容忍度。
		for i := 0; i < 8; i++ {
			w.Write(want[i*1000 : (i+1)*1000])
			f.Flush()
			time.Sleep(40 * time.Millisecond)
		}
	}))
	defer srv.Close()

	got, err := getBlob(srv.Client(), srv.URL, 1<<20, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("慢但一直在走的下载不该失败:%v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("内容不对:%d 字节,期望 %d", len(got), len(want))
	}
}

// 卡住才是故障 —— 而且要快速失败,别把整个取配置周期拖死。
func TestGetBlobAbortsOnStall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("开头这点是有的"))
		w.(http.Flusher).Flush()
		// 然后再也不给了;客户端一断就收工,免得 srv.Close() 干等。
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	}))
	defer srv.Close()

	start := time.Now()
	_, err := getBlob(srv.Client(), srv.URL, 1<<20, 150*time.Millisecond)
	if err == nil {
		t.Fatal("卡住的下载应当报错")
	}
	if !strings.Contains(err.Error(), "卡住") {
		t.Fatalf("错误消息应当说清是卡住了,得到:%v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("应当在停顿容忍度到点后就放弃,实际等了 %v", d)
	}
}

// 上限仍然要拦住 —— 分发点(或中间人)拿无限流吃内存的路子不能因为
// 改了超时就打开。
func TestGetBlobHonorsLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := bytes.Repeat([]byte("y"), 4096)
		for i := 0; i < 100; i++ {
			w.Write(buf)
		}
	}))
	defer srv.Close()

	got, err := getBlob(srv.Client(), srv.URL, 5000, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5000 {
		t.Fatalf("应当截到 5000 字节,得到 %d", len(got))
	}
}
