# Function Templates
[toc]

## 1.1 A First Look at Function Templates
### 1.1.1 template defines

```cpp
template<typename T>
T max (T a, T b)
{
// if b < a then yield a else yield b
return b < a ? a : b;
}
```
该模板定义了一个函数族，其返回该类型的两个值的最大值。`typename T` 是模板参数，语法形式如下：
> `template< comma-separated-list-of-parameters >`

`T`只是一个代号，可以任意指定，但 `T` 是惯例。此例子中，`T` 类型**必须**实现 `<` 操作符定义的方法。
出于历史原因，你可以使用 `class` 替代 `typename`，但容易引起误解，`typename`仍是首选。注意，`struct`并不能用在此处。

### 1.1.2 模板使用

```cpp
#include "max1.hpp"
#include <iostream>
#include <string>
int main()
{
    int i = 42;
    std::cout << "max(7,i): " << ::max(7,i) << ’\n’;
    double f1 = 3.4; double f2 = -6.7;
    std::cout << "max(f1,f2): " << ::max(f1,f2) << ’\n’;
    std::string s1 = "mathematics"; std::string s2 = "math";
    std::cout << "max(s1,s2): " << ::max(s1,s2) << ’\n’;
}
```
`::max()` 为了保证能后找到我们定义的模板函数（因为`std::max()`也定义了）。模板并不是编译成一个单元项从而处理不同的类型，而是有多少类型就编译成多少单元项，比如此处，编译了3中类型的单元项。用具体类型替换模板参数的过程称为实例化。它导致模板的实例。
注意， `void`也是有效的模板参数，前提是生成的代码是有效的
```cpp
template<typename T>
T foo(T*)
{}
void* vp = nullptr;
foo(vp); // OK: deduces void
foo(void*)
```

### 1.1.3 Two-Phase Translation
对不支持模板需要的操作类型作模板实例化会导致错误。
```cpp
std::complex<float> c1, c2; // doesn’t provide operator <
// …
::max(c1,c2); // ERROR at compile time
```
模板分为两步"编译"：
* 在 *definition time*，检查除模板参数之外的模板代码自身正确性，包括：语法错误；使用了不依赖模板参数的未知的名称（类型名称， 函数名称···）；不依赖模板参数的静态断言（static asertions）。
* 在 *instantiation time*，检查模板代码保证所有代码有效。这表示，所有依赖模板参数的部分都需要被检查。

比如：
```cpp
template<typename T>
void foo(T t)
{
    undeclared(); // first-phase compile-time error if undeclared() unknown
    undeclared(t); // second-phase compile-time error if undeclared(T) unknown
    static_assert(sizeof(int) > 10,"int too small"); // always fails if sizeof(int)<=10 
    static_assert(sizeof(T) > 10,"T too small"); //fails if instantiated for T with size <=10 
}
```
检查名称两次称为*two-phase lookup*, 参见14.3.1。 由于在第一阶段检查不完全，所以有些错误在执行第一次实例化之前不会出现。

 **Compiling and Linking**
*Two-phase translation* 导致了在实际中处理模板的一个重要问题：在一个函数模板触发实例化时，编译器（在某个时候）需要模板的定义。这与普通函数的编译和链接是有区别的，编译一个普通函数的调用只需要其声明。处理该问题的方法在第九章讨论。本初讨论最简单的实践：在头文件中实现模板。

## 1.2 模板函数推导
类型推导时的类型转换
注意，在类型推导时类型转换是有限的：
* 当以引用方式声明调用参数，每一次普通转换并不应用于类型推导。以同一类型声明的模板参数必须严格一致。
* 当以传值的方式声明参数，只支持 *decay(退化)* 的普通转换，带有`const`或者`volatile` 的限制会被忽略，引用转换为引用值的类型，原始数组或函数转换为对应的指针类型。对于两个都声明为`T`的模板参数，他们的*decayed*类型必须匹配。

比如：
```cpp
template<typename T>
T max (T a, T b);
// … 
int const c = 42;
max(i, c); // OK: T is deduced as int
max(c, c); // OK: T is deduced as int
int& ir = i;
max(i, ir); // OK: T is deduced as int
int arr[4];
foo(&i, arr); // OK: T is deduced as int*
```
如下则是错误：
```cpp
max(4, 7.2); // ERROR: T can be deduced as int or double 
std::string s;
foo("hello", s); //ERROR: T can be deduced as char const[6] or std::string
```
有三种方式处理错误：
1，cast 参数，使其匹配：
`max(static_cast<double>(4), 7.2);  //OK`
2, 显式指定`T`的类型，从而避免参数推导：
`max<double>(4, 7.2);  //OK`
3, 在模板函数中指明参数具有不同类型

**默认参数的类型推导**
类型推导并不对默认调用参数起作用。比如：
```cpp
template<typename T>
void f(T = "");
//…
f(1); // OK: deduced T to be int, so that it calls f<int>(1)
f(); // ERROR: cannot deduce T
```
为了支持默认调用参数，你需要声明一个默认参数：
```cpp
template<typename T = std::string>
void f(T = "");
// …
f(); // OK
```
## 1.3 多个模板参数
模板函数有两组不同的参数：
+ *Template parameters* 模板参数：
  `template<typename T> // T is template parameter`
+ *Call parameters* 调用参数：
  `T max (T a, T b) // a and b are call parameters`

多个模板参数如下：
```cpp
template<typename T1, typename T2>
T1 max (T1 a, T2 b)
{
    return b < a ? a : b; 
}
//… 
auto  m =::max(4, 7.2); // OK, but type of first argument defines return type
```
这里有个问题：如果使用其中一个模板参数类型作为返回类型，其他参数可能不考虑调用者意图而需要转换到这个类型。因此， 返回类型依赖于调用参数顺序。
C++提供多用方式处理该问题：
+ 引入第三个模板参数作为返回类型
+ 令编译器找出返回类型
+ 声明返回类型为两种参数类型的”common type“
  
### 1.3.1 Template Parameters for Return Types
前边说过，模板参数推导可以是我们以等价于与普通函数的方式使用模板函数：我们不必显式指定相关的模板参数。
但是，也提到可以显式指定模板参数的类型:
```cpp
template<typename T>
T max (T a, T b);
 // …
::max<double>(4, 7.2); // instantiate T as double
```
在无法决定模板参数或者模板和调用参数没有联系时，调用时必须显式指定模板参数。
> 引入第三个模板参数作为返回类型

```cpp
template<typename T1, typename T2, typename RT>
RT max (T1 a, T2 b);
```
参数推导并没有处理返回类型，并且`RT`类型并没有出现在函数的调用参数列表中，因此，`RT`不能被推导出来。
>在C++中，不能从调用方使用调用的上下文中推断返回类型。


因此，必须显式指定模板参数列表：
```cpp
template<typename T1, typename T2, typename RT>
RT max (T1 a, T2 b);
//…
::max<int,double,double>(4, 7.2); // OK, but tedious
```
另一个方式是只指定第一个参数类型，这允许推导出剩余的参数。一般而言，你必须指定所有不能隐式确定的参数。因此，如果，你修改了我们例子中的模板参数顺序，调用者需要指定返回类型：
```cpp
template<typename RT, typename T1, typename T2>
RT max (T1 a, T2 b);
//…
::max<double>(4, 7.2) //OK: return type is double, T1 and T2 are deduced
```
此例中，返回值`RT`为`double`，参数`T1, T2`推到为`int`和`double`.
注意，这个版本并没有明显的优势。但单参数版本简介易使用。

### 1.3.2 Deducing the Return Type
如果返回类型取决于模板参数，那么推导除返回值最好最简单的方式是让编译器找出它。C++14开始，不需要声明返回值就能实现（你仍需要声明返回值为`auto`）:
```cpp
template<typename T1, typename T2>
auto max (T1 a, T2 b)
{
return b < a ? a : b;
}
```
`auto`作为返回类型要求了从函数体返回说明中推断类型。
在C++14之前，只有使函数调用时声明返回值才可以。在C++11中，*trailing return type*语法很有帮助。既，我们可以 *declare* 返回类型派生自 `operator?:` 的结果:

```cpp
template<typename T1, typename T2>
auto max (T1 a, T2 b) -> decltype(b<a?a:b)
{
return b < a ? a : b;
}
```
这里，结果类型取决于规则`operator?:`，如果 a 和 b 具有不同的算术类型，则找到用于结果的通用算术类型。
```cpp
template<typename T1, typename T2>
auto max (T1 a, T2 b) -> decltype(b<a?a:b);
```
是一个声明，使得编译器根据为`a,b`调用`operator?:`规则来找出返回类型。方法实现不必完全匹配。实际上，在声明中使用`true`作为`operator?:`就足够：
```cpp
template<typename T1, typename T2>
auto max (T1 a, T2 b) -> decltype(true?a:b);
```
但其有个缺点：返回值可能是引用类型。为此需要返回`T`退化后的类型：
```cpp
#include <type_traits>
template<typename T1, typename T2>
auto max (T1 a, T2 b) -> typename std::decay<decltype(true?
a:b)>::type
{ 
    return b < a ? a : b;
}
```
因为`::type`是一个类型，所以必须以`typename`修饰的表达式访问它
`typename T::SubType* ptr;`
注意，类型为`auto`的初始化始终是退化的。这也作用于返回类型是`auto`的返回值。`auto`作为返回类型的行为如下所示，其中`a`是`int`类型，由`i`的类型退化所得：

```cpp
int i = 42;
int const& ir = i; // ir refers to i 
auto a = ir; // a is declared as new object of type int
```

### 1.3.3 Return Type as Common Type
自 C++11，标准库提供一种方式来指定更为一般的类型。`std::common_type<>::type`提供了两个（或者更多）不同类型作为模板参数的”一般类型（common type）“。比如：
```cpp
#include <type_traits>
template<typename T1, typename T2>
std::common_type_t<T1,T2> max (T1 a, T2 b)
{
    return b < a ? a : b;
}
```

`std::common_type`是类型特化( *type trait* )，定义在头文件`<type_traits>`中，其为返回类型提供了含有`type`的结构。因此，其核心应用如下：

`typename std::common_type<T1,T2>::type //since C++11`


但从C++14开始，你可以通过像为特化名称添加`_t`和忽略`typename and ::type`等方式使用特化，故返回类型可以简化如下：

`std::common_type_t<T1,T2> // equivalent since C++14`

`std::common_type<>`的实现使用了一些诡异的模板编程，在26.5.2中讨论。内部实现上，其根据操作符`?:`的语言规则或者特殊类型的特殊化类确定返回类型。因此，`::max(4, 7.2)  and ::max(7.2, 4)`都服从于值7.2类型为`double`这一规则。`std::common_type<>`也会退化，参见D.5。

## 1.4 Default Template Arguments
*默认模板参数 default template arguments*可以使用在任意类型模板。
> C++11 之前，默认模板参数只能用于类模板

它们甚至可能引用以前的模板参数。比如你想结合定义返回类型和拥有多个参数类型两个方面，可以为返回类型引入一个模板参数`RT`，其中两个参数的通用类型为默认值。为此，有多个选择：
1，直接使用`operator?:`。但必须在调用参数`a and b`声明之前应用`operator?:`，因此只能使用他们的类型：

```cpp
#include <type_traits>
template<typename T1, typename T2,
typename RT = std::decay_t<decltype(true ? T1() : T2())>>
RT max (T1 a, T2 b)
{
    return b < a ? a : b;
}
```
使用`std::decay_t<>`确保没有引用返回。
>C++11 中使用 `typename std::decay<...>::type`

另请注意，此实现要求我们能够调用传递类型的默认构造函数。有另一个办法，使用`std::declval`,但其使声明更复杂。11.2.3有一个例子。
2，使用`std::common_type<>`类型特化来指定返回类型默认值：

```cpp
#include <type_traits>
template<typename T1, typename T2,
typename RT = std::common_type_t<T1,T2>>
RT max (T1 a, T2 b)
{
return b < a ? a : b;
}
```
`std::common_type<>`退化导致没有引用返回。
在所有情况下，作为调用者，现在可以使用默认值作为返回类型 ：

` auto a = ::max(4, 7.2); `

或者在其他参数类型后显式指定返回类型：

`auto b = ::max<double,int,long double>(7.2, 4);`
仍然有个问题，需要指定三个类型才能确定返回类型。相反，我们需要能够将返回类型作为第一个模板参数，同时仍然能够从参数类型推断出它。原则上，即使没有默认参数的参数遵循，也可以为前导函数模板参数设置默认参数：

```cpp
template<typename RT = long, typename T1, typename T2>
RT max (T1 a, T2 b)
{
return b < a ? a : b;
}
```
有了这个定义，可以这样使用：
```cpp
int i;
long l;
//...
max(i, l);// returns long (default argument of template parameter for return type)
max<int>(4, 42); // returns int as explicitly requested
```

但是，如果模板参数有"自然"默认值，则此方法才有意义。在这里，我们需要模板参数的默认参数依赖于以前的模板参数。原则上，正如我们在第 26.5.1 节中讨论的那样，这是可能的，但技术取决于类型特征，并使定义复杂化。

出于所有这些原因，最好和最简单的解决方案是让编译器推断第 1.3.2 节中建议的返回类型。

## 重载函数模板
 函数模板可以重载。
 ```cpp
 // maximum of two int values:
int max (int a, int b)
{
    return b < a ? a : b;
}
// maximum of two values of any type:
template<typename T>
T max (T a, T b)
{
    return b < a ? a : b;
}
int main()
{
    ::max(7, 42); // calls the nontemplate for two ints
    ::max(7.0, 42.0); // calls max<double> (by argument deduction)
    ::max('a', 'b'); // calls max<char> (by argument deduction)
    ::max<>(7, 42); // calls max<int> (by argument deduction)
    ::max<double>(7, 42); // calls max<double> (no argument deduction)
    ::max('a', 42.7); // calls the nontemplate for two ints
}
 ```
如果模板可以生成匹配更好的函数，则选择该模板:
```cpp
::max(7.0, 42.0); // calls the max<double> (by argument deduction)
::max('a', 'b'); // calls the max<char> (by argument deduction)
```
这里模板比普通函数匹配更好，因此没有必要将`double`转换为`int` 或者将 `char` 转换为 `int`。
还可以显式指定空模板参数列表。此语法指示只有模板可以解决调用，但所有模板参数都应从调用参数推断
```cpp
::max<>(7, 42); // calls max<int> (by argument deduction)
```
由于推导模板参数不考虑自动类型转换，但考虑用于普通函数参数，因此最后一次调用使用非模板函数:
```cpp
::max('a', 42.7); // only the nontemplate function allows nontrivial conversions
```

一个有趣的示例是重载 maximum 模板，以便仅显式指定返回类型:
```cpp
template<typename T1, typename T2>
auto max (T1 a, T2 b)
{
return b < a ? a : b;
}
template<typename RT, typename T1, typename T2>
RT max (T1 a, T2 b)
{
return b < a ? a : b;
}
```

现在，调用`max()`，：
```cpp
auto a = ::max(4, 7.2); // uses first template
auto b = ::max<long double>(7.2, 4); // uses second template
```

但当我们作如下调用：
```cpp
auto c = ::max<int>(4, 7.2); // ERROR: both function templates match
```

两个模板都匹配，这会导致过载解析过程通常首选 none，并导致歧义错误。因此，在重载函数模板时，应确保其中只有一个模板与任何调用匹配。

一个有用的示例是重载指针和普通 C 字符串的maximum 模板：
```cpp
#include <cstring>
#include <string>
// maximum of two values of any type:
template<typename T>
T max (T a, T b)
{
    return b < a ? a : b;
}
// maximum of two pointers:
template<typename T>
T* max (T* a, T* b)
{
    return *b < *a ? a : b;
}
// maximum of two C-strings:
char const* max (char const* a, char const* b)
{
    return std::strcmp(b,a) < 0 ? a : b;
}
int main ()
{
    int a = 7;
    int b = 42;
    auto m1 = ::max(a,b); // max() for two values of type int
    std::string s1 = "hey";
    std::string s2 = "you";
    auto m2 = ::max(s1,s2); // max() for two values of type std::string
    int* p1 = &b;
    int* p2 = &a;
    auto m3 = ::max(p1,p2); // max() for two pointers
    char const* x = "hello";
    char const* y = "world";
    auto m4 = ::max(x,y); // max() for two C-strings
}
```
在 `max()`所有重载中都是传值。通常，在重载函数模板时，最好不要更改超过必要的更改。应将更改限制为参数数或显式指定模板参数。否则，可能会出现意外效果。例如，如果实现`max()`模板通过引用传递参数，并重载两个按值传递的 C 字符串，则不能使用三参数版本计算三个 C 字符串的最大值：
```cpp
#include <cstring>
// maximum of two values of any type (call-by-reference)
template<typename T>
T const& max (T const& a, T const& b)
{
    return b < a ? a : b;
}
// maximum of two C-strings (call-by-value)
char const* max (char const* a, char const* b)
{
    return std::strcmp(b,a) < 0 ? a : b;
}
// maximum of three values of any type (call-by-reference)
template<typename T>
T const& max (T const& a, T const& b, T const& c)
{
    return max (max(a,b), c); // error if max(a,b) uses call-by-value
}
int main ()
{
    auto m1 = ::max(7, 42, 68); // OK
    char const* s1 = "frederic";
    char const* s2 = "anica";
    char const* s3 = "lucas";
    auto m2 = ::max(s1, s2, s3); // run-time ERROR
}
```
如果调用如下：

`return max (max(a,b), c);`

就成了运行时错误，因为`max(a,b)`以引用的方式返回了一个新的临时局部值，但返回语句完成后临时变量就失效了，离开`main()`后留下悬挂引用，不幸的是，这个错误是相当微妙的，可能不会在所有情况下都显现出来。
请注意，相反，在 `main()` 中对 `max()` 的第一次调用不会受到相同的问题。为参数（7、42 和 68）创建临时参数，但这些临时参数在 main（） 中创建，它们一直存在，直到语句完成。

请确保在调用函数之前声明函数的所有重载版本。这是因为在进行相应的函数调用时，并非所有重载函数都可见这一事实可能很重要。例如，在未看到 int 的特殊双参数版本声明的情况下定义 `max()` 的三参数版本会导致三参数版本使用双参数模板:
```cpp
#include <iostream>
// maximum of two values of any type:
template<typename T>
T max (T a, T b)
{
    std::cout << "max<T>() \n";
    return b < a ? a : b;
}
// maximum of three values of any type:
template<typename T>
T max (T a, T b, T c)
{
    return max (max(a,b), c); // uses the template version even for ints
} // because the following declaration comes
// too late:
// maximum of two int values:
int max (int a, int b)
{
    std::cout << "max(int,int) \n";
    return b < a ? a : b;
}
int main()
{
    ::max(47,11,33); // OOPS: uses max<T>() instead of max(int,int)
}
```
在13.2节讨论这个。

## 1.6 More
可能，即使是这些简单的函数模板示例也可能引发更多问题。三个问题可能非常普遍，我们应该在这里简要地讨论一下。

### 1.6.1 Pass by Value or by Reference?
你可能想知道，为什么我们一般声明函数以按值传递参数，而不是使用引用。通常，建议对简单类型（如基本类型或 `std::string_view`）以外的类型推荐通过引用传递，因为不会创建不必要的副本。但是，出于几个原因，按值传递通常更好:
+ 语法很简单。
+ 编译器优化更好。
+ 移动语义通常使拷贝开销更少。
+ 有时根本没有拷贝或移动

此外，对于模板，具体方面也发挥作用：
+ 模板可用于简单类型和复杂类型，因此为复杂类型选择方法对简单类型可能适得其反。
+ 作为调用方，你通常仍可以决定通过引用传递参数，使用 `std::ref()` 和 `std::cref()`（参见第 112 页的第 7.3 节）。
+ 尽管传递字符串文本或原始数组总是会成为一个问题，但通过引用传递它们通常被视为更大的问题。

所有这一切将在第7章中详细讨论。在书内，我们通常会按值传递参数，除非某些功能仅在使用引用时才可以。

### 1.6.2 Why Not inline?
通常，函数模板不必使用内联声明。与普通非内联函数不同，我们可以在头文件中定义非内联函数模板，并将此头文件包含在多个转换单元中。此规则的唯一例外是特定类型的模板的完整专用化，因此生成的代码不再是泛型（定义了所有模板参数）。有关详细信息，请参阅第 9.2 节。
从严格的语言定义的角度来看，内联仅意味着函数的定义可以在程序中多次出现。但是，它也意味着对编译器的提示，即调用该函数应"内联扩展"：这样做可以生成某些情况下的更高效的代码，但也可能降低许多其他情况下的代码效率。如今，编译器通常更善于在没有内联关键字暗示的提示的情况下来决定这一点。但是，编译器仍考虑该决定中内联的存在。

### 1.6.3 Why Not constexpr?
从C++11开始，你可以使用 constexpr 提供在编译时使用代码计算某些值的能力。对于许多模板，这是有意义的。
例如，为了能够在编译时使用`max()`函数，你必须按照以下方式声明它：
```cpp
template<typename T1, typename T2>
constexpr auto max (T1 a, T2 b)
{
    return b < a ? a : b;
}
```
这样，你可以在具有编译时上下文的位置使用最大函数模板，例如，在声明原始数组的大小时：

`int a[::max(sizeof(char),1000u)];`

或者 `std::array<>` 的大小：

`std::array<std::string, ::max(sizeof(char),1000u)> arr;`

8.2节将会讨论`constexpr`的其他例子。为了保持专注，我们一般在讨论其他模板特点时忽略它。

## 1.7 总结

+ 函数模板为不同的模板参数定义函数系列。
+ 将参数传递给函数参数（具体取决于模板参数）时，函数模板将推导出要实例化的相应参数类型的模板参数。
+ 你可以显式限定前导模板参数。
+ 你可以为模板参数定义默认参数。这些参数可能引用以前的模板参数，后面是没有默认参数的参数。
+ 可以重载函数模板。
+ 当使用其他函数模板重载函数模板时，应确保只有一个模板与任何调用匹配。
+ 重载函数模板时，将更改限制为显式指定模板参数。
+ 确保编译器在调用函数模板之前得到所有重载版本的函数模板。