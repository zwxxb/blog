---
title: "- Introduction To V8 Pwning "
tags:
  - Pwn
  - CTF
  - heap
  - V8
---

**V8** is a program that compiles **JavaScript** **into bytecode**, translates that **bytecode** into machine language at runtime, and executes it. This is called **just-in-time compilation (JIT compilation**). **Bytecode** is a type of **intermediate representation (IR) that translates** high-level language into something the virtual machine can understand. The code translated into bytecode is then translated back into machine language when it is finally executed and processed in hardware. This allows **V8** to optimize the given code at runtime, which dramatically speeds up the execution **of JavaScript**.

However, this can cause a variety of problems. For example, if the arguments to a function are consistently integers, **V8** will assume the input is integers and optimize for them. However, if the argument to that optimized function is suddenly an array, **V8** has to de-optimize the code internally, which can lead to issues like **type confusion,** **out-of-bounds (OOB** ) **,** and **use-after-free (UAF**) if the code doesn't recognize **the conditions under which it needs to de-optimize**, or if it misunderstands **the lifecycle of** an object.

**【V8】pwncollege V8 Exploitation - Level 1** 

#### patch(1) - In the first patch (bootstrapper.cc), a new function named "run" is added to the Array prototype:

```diff
diff --git a/src/init/bootstrapper.cc b/src/init/bootstrapper.cc
index 48249695b7b..40a762c24c8 100644
--- a/src/init/bootstrapper.cc
+++ b/src/init/bootstrapper.cc
@@ -2533,6 +2533,8 @@ void Genesis::InitializeGlobal(Handle<JSGlobalObject> global_object,
 
    SimpleInstallFunction(isolate_, proto, "at", Builtin::kArrayPrototypeAt, 1,
                          true);
+    SimpleInstallFunction(isolate_, proto, "run",
+                          Builtin::kArrayRun, 0, false);
    SimpleInstallFunction(isolate_, proto, "concat",
                          Builtin::kArrayPrototypeConcat, 1, false);
    SimpleInstallFunction(isolate_, proto, "copyWithin",
``` 

- This patch calls SimpleInstallFunction to make run available as Array.prototype.run. Internally, it links the JavaScript-visible function name "run" to a V8 C++ builtin called Builtin::kArrayRun.

#### patch(2) - In the second patch (typer.cc), the V8 compiler’s type system is updated so that calls to ArrayRun are appropriately recognized and assigned a type:

```diff
diff --git a/src/compiler/typer.cc b/src/compiler/typer.cc
index 9a346d134b9..58fd42e59a4 100644
--- a/src/compiler/typer.cc
+++ b/src/compiler/typer.cc
@@ -1937,6 +1937,8 @@ Type Typer::Visitor::JSCallTyper(Type fun, Typer* t) {
      return Type::Receiver();
    case Builtin::kArrayUnshift:
      return t->cache_->kPositiveSafeInteger;
+	case Builtin::kArrayRun:
+	  return Type::Receiver();
 
    // ArrayBuffer functions.
    case Builtin::kArrayBufferIsView:
```
- Here, Builtin::kArrayRun is mapped to Type::Receiver(), meaning the result of calling this builtin is expected to be something that can act as a JavaScript “receiver.” In practice, this typically means the builtin doesn’t return (or requires) a traditional numeric or string type. 

#### The newly introduced builtin ArrayRun is shown below. It is defined alongside other Array builtins (e.g., ArrayPush, ArrayPop, etc.):

```c++
@@ -407,6 +409,47 @@ BUILTIN(ArrayPush) {
  return *isolate->factory()->NewNumberFromUint((new_length));
}

+BUILTIN(ArrayRun) {
+  HandleScope scope(isolate);
+  Factory *factory = isolate->factory();
+  Handle<Object> receiver = args.receiver();
+
+  if (!IsJSArray(*receiver) || !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver))) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Nope")));
+  }
+
+  Handle<JSArray> array = Cast<JSArray>(receiver);
+  ElementsKind kind = array->GetElementsKind();
+
+  if (kind != PACKED_DOUBLE_ELEMENTS) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("Need array of double numbers")));
+  }
+
+  uint32_t length = static_cast<uint32_t>(Object::NumberValue(array->length()));
+  if (sizeof(double) * (uint64_t)length > 4096) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("array too long")));
+  }
+
+  // mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
+  double *mem = (double *)mmap(NULL, 4096, 7, 0x22, -1, 0);
+  if (mem == (double *)-1) {
+    THROW_NEW_ERROR_RETURN_FAILURE(isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
+      factory->NewStringFromAsciiChecked("mmap failed")));
+  }
+
+  Handle<FixedDoubleArray> elements(Cast<FixedDoubleArray>(array->elements()), isolate);
+  FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
+    double x = elements->get_scalar(i);
+    mem[i] = x;
+  });
+
+  ((void (*)())mem)();
+  return 0;
+}
+
namespace {

V8_WARN_UNUSED_RESULT Tagged<Object> GenericArrayPop(Isolate* isolate,
```

## Explanation - Baby steps

1. **Checking the receiver**
    
    The builtin first checks whether the caller (i.e., `this` in JavaScript) is actually a `JSArray` and if it uses “simple receiver elements.” In V8, a “simple array” is one that:
    
    - Has continuous integer indices (no gaps).
    - Has not been converted to a different structure (e.g., sparse array or special dictionary).
    - Does not use object keys or symbol keys instead of numeric indices.
    
    If any of these checks fail, it throws a `TypeError` with a placeholder message ("Nope").
    
2. **Validating the Element Kind**
    
    After confirming it is indeed a `JSArray`, the builtin checks the array’s element kind with `array->GetElementsKind()`. It must be `PACKED_DOUBLE_ELEMENTS`, meaning each element is stored as a 64-bit floating-point number. If the array holds anything else (e.g., integers, objects, or holes), it throws an error: “Need array of double numbers.”
    
3. **Length and Memory Safety Check**
    
    The code reads the `length` property and calculates how many bytes the array would need in memory (each element is `sizeof(double)`). It then checks if this amount exceeds 4096 bytes. If it does, an error is thrown. This is effectively limiting the array size to a small buffer (to avoid more complex memory handling).
    
4. **Mapping Memory (mmap) with Execute Permission**
    
    The builtin calls `mmap` to allocate 4096 bytes of memory with read, write, and execute permissions (the flags `PROT_READ | PROT_WRITE | PROT_EXEC` and `MAP_PRIVATE | MAP_ANONYMOUS`). This is unusual in normal application code because it requests an RWX memory region, which can be risky from a security standpoint. RWX memory allows writing arbitrary bytes, then executing them as machine code.
    
    - If the mapping fails, the code throws a `TypeError` with the message “mmap failed.”
5. **Transferring Array Data into Executable Memory**
    
    The builtin copies each double value from the array into the newly mapped memory:

```c++
FOR_WITH_HANDLE_SCOPE(isolate, uint32_t, i = 0, i, i < length, i++, {
  double x = elements->get_scalar(i);
  mem[i] = x;
});
```
- Each floating-point element is placed consecutively in the mem buffer.

6. **Jumping into the Mapped Memory**
    Finally, the code casts `mem` to a function pointer (`(void (*)())mem`) and immediately calls that function via `((void (*)())mem)();`. This means that the double values in the array are now treated as raw processor instructions, which the CPU will attempt to execute.
    
    In practice, whatever the floating-point array data corresponds to as machine code will run. This can have serious implications if the data is crafted in a certain way—this is effectively a form of dynamic code generation.
    
7. **Return Value**
    After the function call returns (if it returns at all), the builtin ends by returning `0` to JavaScript.


```
            ┌─────────────────────────────────────────┐
            │       JavaScript Array (doubles)        │
            │  [0]  0x4085C28F5C28F5C3 (first double) │
            │  [1]  0x4034000000000000 (second)       │
            │  [2]  ...                               │
            └─────────────────────────────────────────┘
                         │   (1) Check array kind and size
                         │   (2) Map 4096 bytes as RWX
                         ▼
            ┌─────────────────────────────────────────┐
            │    RWX Memory (mmap-ed) 4096 bytes      │
            │  [0]  0x4085C28F5C28F5C3 (machine code?)│
            │  [1]  0x4034000000000000                │
            │  [2]  ...                               │
            └─────────────────────────────────────────┘
                         │   (3) Copy doubles to RWX memory
                         ▼
            ┌─────────────────────────────────────────┐
            │((void(*)())mem)() => Code Execution!    │
            │ The double data is treated as opcodes   │
            └─────────────────────────────────────────┘
```

