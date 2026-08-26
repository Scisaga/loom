package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPullRejectsUnsafeNodeIDBeforeNetwork(t *testing.T) {
	err := cmdPull([]string{"-url", "http://127.0.0.1:1", "-node", "../escape"})
	if err == nil || !strings.Contains(err.Error(), "节点 id") {
		t.Fatalf("危险 node id 未在拼 URL 前拒绝:%v", err)
	}
}

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

func TestGetBlobTotalDeadlineStopsDripFeed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := w.(http.Flusher)
		for {
			if _, err := w.Write([]byte("x")); err != nil {
				return
			}
			f.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}))
	defer srv.Close()

	start := time.Now()
	_, err := getBlobWithLimits(srv.Client(), srv.URL, 1<<20, 60*time.Millisecond, 140*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "总时限") {
		t.Fatalf("持续滴字节应由独立总时限终止，得到:%v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("总时限没有及时生效:%s", elapsed)
	}
}

func TestBlobTotalTimeoutIsSizeBasedAndBounded(t *testing.T) {
	if got := blobTotalTimeout(1); got != blobTotalMinimum {
		t.Fatalf("小文件总时限=%s, want min %s", got, blobTotalMinimum)
	}
	medium := blobTotalTimeout(32 << 20)
	large := blobTotalTimeout(48 << 20)
	if medium <= blobTotalMinimum || large <= medium {
		t.Fatalf("总时限没有随签名 size 增长:medium=%s large=%s", medium, large)
	}
	if got := blobTotalTimeout(1 << 40); got != blobTotalMaximum {
		t.Fatalf("超大 size 没有被 max 截断:%s", got)
	}
}
