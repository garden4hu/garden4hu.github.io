[toc]

与函数类似，类也可以使用一种或多种类型进行参数化。用于管理特定类型元素的容器类是此功能的典型示例。通过使用类模板，可以在元素类型仍然打开时实现此类容器类。在本章中，我们将堆栈用作类模板的示例。

## 2.1 Implementation of Class Template Stack
在头文件中声明 `Stack<>` 如下：
```cpp
#include <vector>
#include <cassert>
template<typename T>
class Stack {
private:
    std::vector<T> elems; // elements
public:
    void push(T const& elem); // push element
    void pop(); // pop element
    T const& top() const; // return top element
    bool empty() const { // return whether the stack is empty
        return elems.empty();
    }
};

template<typename T>
void Stack<T>::push (T const& elem)
{
    elems.push_back(elem); // append copy of passed elem
}
template<typename T>
void Stack<T>::pop ()
{
    assert(!elems.empty());
    elems.pop_back(); // remove last element
}
template<typename T>
T const& Stack<T>::top () const
{
    assert(!elems.empty());
    return elems.back(); // return copy of last element
}
```

这个类模板是通过使用C++标准库`vector<>`的类模板实现的，因此，不必实现内存管理，拷贝构造，赋值操作符。这样可以集中关注类模板的接口。

### 2.1.1 Declaration of Class Templates
类模板的声明类似于函数模板：在声明之前，必须声明一个或多个标识符作为类型参数：
```cpp
template<typename T>
class Stack {
//...
};
```
此处， `class`可以替换`typename`:
```cpp
template<class T>
class Stack {
//...
};
```
在类模板中，T 可以像任何其他类型一样用于声明成员和成员函数。上面定义的类的类型是`Stack<T>`，`T`是模板参数。无论何时，只要使用此类型的类，都必须使用`Stack<T>`,除非模板参数能够推导出来。但是，在类模板中使用不带模板参数的类名表示以其模板参数作为其参数的类（参见13.2.3）。
如果你需要定义自己的拷贝构造函数和赋值操作符，一般像这样：
```cpp
template<typename T>
class Stack {
// ...
Stack (Stack const&); // copy constructor
Stack& operator= (Stack const&); // assignment operator
// ...
};
```
这等同于：
```cpp
template<typename T>
class Stack {
...
Stack (Stack<T> const&); // copy constructor
Stack<T>& operator= (Stack<T> const&); // assignment operator
...
};
```
但通常`<T>`表示特殊模板参数的特殊处理，因此通常最好使用第一种形式。
但，在类结构体外，你还需要写成如下形式：
```cpp
template<typename T>
bool operator== (Stack<T> const& lhs, Stack<T> const& rhs);
```
请注意，在需要名称而不是类类型的地方，只能使用Stack。
当指定构造函数的名称（而不是其参数）和析构函数的名称时，尤其如此。另请注意，与非模板类不同，您不能在函数或块作用域内声明或定义类模板。 通常，只能在全局/命名空间范围或类声明中定义模板.

### 2.1.2 Implementation of Member Functions
要定义类模板的成员函数，必须指定它是模板，并且必须使用类模板的完整类型限定。类型`Stack<T>`的成员函数`push()`看起来像这样:
```cpp
template<typename T>
void Stack<T>::push (T const& elem)
{
    elems.push_back(elem); // append copy of passed elem
}
```
请注意，vector 的`pop_back()`会删除最后一个元素，但不会返回它。此行为的原因是异常安全。无法实现`pop()`的完全异常安全版本来返回已删除的元素。但是，忽略这种危险，我们可以实现一个`pop()`来返回刚刚删除的元素。为此，我们只需使用T声明一个元素类型的局部变量:
```cpp
template<typename T>
T Stack<T>::pop ()
{
    assert(!elems.empty());
    T elem = elems.back(); // save copy of last element
    elems.pop_back(); // remove last element
    return elem; // return copy of saved element
}
```

当向量中没有元素时，因为`back()`（返回最后一个元素）和`pop_back()`（除去最后一个元素）具有未定义的行为，所以我们决定检查堆栈是否为空。如果为空，我们断言，因为在空堆栈上调用pop()是使用错误。也可以在top()中完成该操作，尝试删除不存在的top元素时，该方法返回但不删除top元素:
```cpp
template<typename T>
T const& Stack<T>::top () const
{
    assert(!elems.empty());
    return elems.back(); // return copy of last element
}
```
当然，对于任何成员函数，您还可以将类模板的成员函数实现为类声明中的内联函数。例如:
```cpp
template<typename T>
class Stack {
//...
void push (T const& elem) {
    elems.push_back(elem); // append copy of passed elem
}
// ...
};
```
## 2.2 Use of Class Template Stack
要使用类模板的对象，在C++17之前，必须始终明确指定模板参数。以下示例显示如何使用类模板`Stack<>`:
```cpp
#include "stack1.hpp"
#include <iostream>
#include <string>
int main()
{
    Stack<int> intStack; // stack of ints
    Stack<std::string> stringStack; // stack of strings
    // manipulate int stack
    intStack.push(7);
    std::cout << intStack.top() << '\n';
    // manipulate string stack
    stringStack.push("hello");
    std::cout << stringStack.top() << '\n';
    stringStack.pop();
}
```
> C++17引入了类参数模板推导，如果可以从构造函数派生模板参数，则可以跳过模板参数(2.9节介绍)

请注意，*仅为调用的模板(成员)函数*实例化代码。对于类模板，仅在使用成员函数时实例化它们。当然，这可以节省时间和空间，并且仅允许部分使用类模板，在2.3节讨论。
在这个例子中，`push() and top()`为`int and string`进行了初始化，然而，`pop()`仅为string进行了初始化。如果类模板具有静态成员，则对于使用该类模板的每种类型，这些成员也会被实例化一次。
实例化类模板的类型可以像其他任何类型一样使用。您可以使用const或volatile对其进行限定，或者从中派生数组和引用类型。您还可以将其用作typedef的类型定义的一部分，或者在构建另一个模板类型时将其用作类型参数。例如：
```cpp
void foo(Stack<int> const& s) // parameter s is int stack
{
    using IntStack = Stack<int>; // IntStack is another name for Stack<int>
    Stack<int> istack[10]; // istack is array of 10 int stacks
    IntStack istack2[10]; // istack2 is also an array of 10 int stacks (same type)
    //...
}
```
模板参数可以是任何类型，例如float 指针或甚至是Stack<int>：
```cpp
Stack<float*> floatPtrStack; // stack of float pointers
Stack<Stack<int>> intStackStack; // stack of stack of ints
```
唯一的要求是,此类型的任何调用的操作都是可以的。

> C++11 之前，`Stack<Stack<int> >` 才可以
出现这种旧行为的原因是，它帮助C++编译器的首次通过来独立于代码的语义来标记源代码。但是，由于缺少的空格是一个典型的错误，需要相应的错误消息，因此无论如何，越来越多的代码必须考虑到代码的语义。因此，在C++11中，删除了在两个闭合模板括号之间放置空格的规则。