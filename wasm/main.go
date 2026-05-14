//go:build js && wasm

package main

import (
	"runtime"
	"runtime/debug"
	"syscall/js"
)

// wasmHeap is the module-level buffer store used by AllocateBufferWasm and
// FreeBufferWasm. Keys are opaque integer "pointers" starting at 1.
var wasmHeap = make(map[int][]byte)

// heapCounter is the next pointer value to assign. Starts at 1 so that 0
// can be used as a sentinel "null pointer".
var heapCounter = 1

// AllocateBufferWasm allocates a buffer of the requested size in the
// module-level heap map and returns its pointer as a js.Value.
//
// JS signature: allocateBuffer(size: number): number
//
// args[0] – size (int): number of bytes to allocate (must be > 0)
//
// Returns the integer pointer on success, or js.Undefined() on error.
//
// Requisitos: 11.2, 11.4
func AllocateBufferWasm(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return js.Undefined()
	}
	size := args[0].Int()
	if size <= 0 {
		return js.Undefined()
	}

	ptr := heapCounter
	heapCounter++
	wasmHeap[ptr] = make([]byte, size)
	return js.ValueOf(ptr)
}

// FreeBufferWasm frees the buffer at the given pointer from the heap map.
//
// JS signature: freeBuffer(pointer: number): void
//
// args[0] – pointer (int): the pointer returned by AllocateBufferWasm
//
// Requisitos: 11.2, 11.4
func FreeBufferWasm(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return js.Undefined()
	}
	ptr := args[0].Int()
	delete(wasmHeap, ptr)
	return js.Undefined()
}

// ProcessBytesWasm reads the buffer at the given pointer from the heap map,
// calls ObfuscateStream with the provided state, concatenates the resulting
// chunks into a new buffer, stores it in the heap, and returns the new pointer.
//
// JS signature: processBytes(pointer: number, length: number, state: number): number
//
// args[0] – pointer (int): pointer to the input buffer in wasmHeap
// args[1] – length  (int): number of bytes to read from the buffer
// args[2] – state   (int): evasion state code (0x01, 0x02, or 0x03)
//
// Returns the integer pointer to the result buffer, or js.Undefined() on error.
//
// Requisitos: 11.2, 11.4
func ProcessBytesWasm(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return js.Undefined()
	}

	ptr := args[0].Int()
	length := args[1].Int()
	state := args[2].Int()

	// Look up the input buffer in the heap.
	buf, ok := wasmHeap[ptr]
	if !ok {
		return js.Undefined()
	}

	// Clamp length to the actual buffer size.
	if length > len(buf) {
		length = len(buf)
	}
	rawBuffer := buf[:length]

	// Apply obfuscation.
	chunks, err := ObfuscateStream(rawBuffer, state)
	if err != nil || len(chunks) == 0 {
		return js.Undefined()
	}

	// Concatenate all result chunks into a single output buffer.
	totalLen := 0
	for _, chunk := range chunks {
		totalLen += len(chunk)
	}
	result := make([]byte, totalLen)
	offset := 0
	for _, chunk := range chunks {
		copy(result[offset:], chunk)
		offset += len(chunk)
	}

	// Store the result in the heap and return its pointer.
	resultPtr := heapCounter
	heapCounter++
	wasmHeap[resultPtr] = result
	return js.ValueOf(resultPtr)
}

// TriggerGCWasm invokes the Go garbage collector on demand.
//
// JS signature: triggerGC(): void
//
// Requisitos: 11.2, 11.4
func TriggerGCWasm(this js.Value, args []js.Value) any {
	runtime.GC()
	return js.Undefined()
}

func main() {
	// Configure GOGC=50 to reduce maximum heap size at the cost of more
	// frequent GC cycles with shorter individual pauses (REQ-NF GC tuning).
	// Requisito: 11.4
	debug.SetGCPercent(50)

	// Register exported functions in the JS global scope.
	js.Global().Set("processBytes", js.FuncOf(ProcessBytesWasm))
	js.Global().Set("allocateBuffer", js.FuncOf(AllocateBufferWasm))
	js.Global().Set("freeBuffer", js.FuncOf(FreeBufferWasm))
	js.Global().Set("triggerGC", js.FuncOf(TriggerGCWasm))
	js.Global().Set("ppoBridgeReady", js.ValueOf(true))

	// Keep the Go runtime alive indefinitely so the exported functions
	// remain callable from JavaScript.
	select {}
}
