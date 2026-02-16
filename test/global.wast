(module
  ;; Immutable i32 global
  (global $g0 i32 (i32.const 42))
  ;; Mutable i32 global
  (global $g1 (mut i32) (i32.const 0))
  ;; Immutable i64 global
  (global $g2 i64 (i64.const 1000000000000))

  ;; Read immutable i32 global
  (func (export "get_g0") (result i32)
    global.get $g0
  )

  ;; Read mutable i32 global (initial value)
  (func (export "get_g1") (result i32)
    global.get $g1
  )

  ;; Set and read mutable i32 global
  (func (export "set_get_g1") (param i32) (result i32)
    local.get 0
    global.set $g1
    global.get $g1
  )

  ;; Read i64 global
  (func (export "get_g2") (result i64)
    global.get $g2
  )

  ;; Use global as counter: add n to g1 and return new value
  (func (export "add_g1") (param i32) (result i32)
    global.get $g1
    local.get 0
    i32.add
    global.set $g1
    global.get $g1
  )
)

;; Test immutable i32 global
(assert_return (invoke "get_g0") (i32.const 42))

;; Test mutable i32 global initial value
(assert_return (invoke "get_g1") (i32.const 0))

;; Test set and get mutable i32 global
(assert_return (invoke "set_get_g1" (i32.const 7)) (i32.const 7))

;; After set, get should return new value
(assert_return (invoke "get_g1") (i32.const 7))

;; Test i64 global
(assert_return (invoke "get_g2") (i64.const 1000000000000))

;; Test global as counter
(assert_return (invoke "add_g1" (i32.const 3)) (i32.const 10))
(assert_return (invoke "add_g1" (i32.const 5)) (i32.const 15))
(assert_return (invoke "get_g1") (i32.const 15))
