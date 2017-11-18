\# 基础议题

## 1.指针与引用的区别

首先，在任何情况下都不能使用指向空值的引用。一个引用必须总是指向某些对象。若一个变量在某些时候可能不指向某些对象，之歌时候应该声明为指针，因为可以赋空值给该变量。

```
    char *pc = 0; //设置指针为空值

    char& rc = *pc; //error 让引用指向空值
```

引用必须初始化。

```cpp
    string& rs; //error 引用必须初始化

    string s("xyz");

    string& rs = s; //OK rs指向s
```

指针没有这样的限制。

```
    string *ps; //ok 未初始化的指针，合法但危险
```

不存在指向空值的引用意味着使用引用的代码效率比使用指针要高。在使用引用之前不需要测试其合法性。

指针与引用的另一个重要的不同是指针可以被重新赋值以指向另一个不同的对象。但是引用则总是指向在初始化时被指定的对象，以后不能改变。

总的来说，在以下情况下你应该 \*\*使用指针\*\* ， \*\*一是你考虑到存在不指向任何对象的可能\*\* （在这种情况下，你能够设置指针为空）， \*\*二是你需要能够在不同的时刻指向不同的对象\*\* （在这种情况下，你能改变指针的指向）。如果总是指向一个对象并且一旦指向一个对象后就不会改变指向，那么你应该使用引用。

另外一个情形，当重载某个操作符时，也应该使用引用。举例：

```
vector<int> v(10); 

v[5] = 10; //这个被赋值的目标就是操作符[]返回的值

 //如果操作符[]返回一个指针，那么后一个语句如下：

*v[5] = 10; //但这样使得v看上去像是一个响亮指针
```

当你知道你必须指向一个对象并且不想改变其指向时，或者在重载操作符并为防止不必要的语义误解时，你不应该使用指针。而在除此之外的其他情况下，则应使用指针。

## 2. 尽量使用C++风格类型

C++通过引进四个新的类型转换操作符克服了C风格类型转换的缺点，这四个操作符是, static\_cast, const\_cast, dynamic\_cast, 和reinterpret\_cast。

```
    static\_cast在功能上基本上与C风格的类型转换一样强大，含义也一样。它也有功能上限制。例如，你不能用static\_cast象用C风格的类型转换一样把struct转换成int类型或者把double类型转换成指针类型，另外，static\_cast不能从表达式中去除const属性，因为另一个新的类型转换操作符const\_cast有这样的功能。

   const\_cast用于类型转换掉表达式的const或volatileness属性。通过使用const\_cast，你向人们和编译器强调你通过类型转换想做的只是改变一些东西的constness或者 volatileness属性。这个含义被编译器所约束。如果你试图使用const\_cast来完成修改constness 或者volatileness属性之外的事情，你的类型转换将被拒绝。下面是一些例子：
```

```cpp
class Widget { ... };
class SpecialWidget: public Widget { ... };
void update(SpecialWidget *psw);
SpecialWidget sw; // sw 是一个非const 对象。
const SpecialWidget& csw = sw; // csw 是sw的一个引用 它是一个const 对象
update(&csw); // 错误!不能传递一个const SpecialWidget\* 变量
 // 给一个处理SpecialWidget*类型变量的函数
update(const_cast<SpecialWidget>(&csw));// 正确，csw的const被显示地转换掉（
 // csw和sw两个变量值在update函数中能被更新
update((SpecialWidget*)&csw);// 同上，但用了一个更难识别的C风格的类型转换
Widget *pw = new SpecialWidget;
update(pw); // 错误！pw的类型是Widget*,但是
//update函数处理的是SpecialWidget*类型]\(//update函数处理的是SpecialWidget*类型) 
update(const_cast<SpecialWidget>(pw));// 错误！const_cast仅能被用在影响
// constness or volatileness的地方上。,
// 不能用在向继承子类进行类型转换。
```

第二种特殊的类型转换符是dynamic\_cast，它被用于安全地沿着类的继承关系向下进行类型转换。这就是说，你能用dynamic\_cast把指向基类的指针或引用转换成指向其派生类或其兄弟类的指针或引用，而且你能知道转换是否成功。失败的转换将返回空指针（当对指针进行类型转换时）或者抛出异常（当对引用进行类型转换时）：

```cpp
Widget *pw;
...
update(dynamic_cast<SpecialWidget>(pw));// 正确，传递给update函数一个指针是指向变量类型为SpecialWidget的pw的指针
// 如果pw确实指向一个对象,否则传递过去的将使空指针。
void updateViaRef(SpecialWidget& rsw);
updateViaRef(dynamic_cast<SpecialWidget&>(*pw));//正确。 传递给updateViaRef函数
// SpecialWidget pw 指针，如果pw确实指向了某个对象,否则将抛出异常
```

dynamic\_casts在帮助你浏览继承层次上是有限制的。它不能被用于缺乏虚函数的类型。

```
    reinterpret\_cast。使用这个操作符的类型转换，其的转换结果几乎都是执行期定义（implementation-defined）。因此，使用reinterpret\_casts的代码很难移植。reinterpret\_casts的最普通的用途就是在函数指针类型之间进行转换。例如，假设你有一个函数指针数组：
```

```cpp
typedef void (*FuncPtr)(); // FuncPtr is 一个指向函数的指针，该函数没有参数.返回值类型为void
FuncPtr funcPtrArray[10]; // funcPtrArray 是一个能容纳10个FuncPtrs指针的数组
```

让我们假设你希望（因为某些莫名其妙的原因）把一个指向下面函数的指针存入funcPtrArray数组：

```cpp
int doSometing();
```

你不能不经过类型转换而直接去做，因为doSomething函数对于funcPtrArray数组来说有一个错误的类型。在FuncPtrArray数组里的函数返回值是void类型，而doSomething函数返回值是int类型。

```cpp
funcPtrArra[0] = &doSomething; // 错误！类型不匹配
//reinterpret_cast可以让你迫使编译器以你的方法去看待它们：
funcPtrArray[0] = // this compiles
reinterpret_cast<FuncPt>(&doSomething);
```

转换函数指针的代码是不可移植的（C++不保证所有的函数指针都被用一样的方法表示），在一些情况下这样的转换会产生不正确的结果，所以你应该避免转换函数指针类型。

## 3.不要对数组使用多态

类继承的最重要的特性是你可以通过基类指针或引用来操作派生类。C++允许你通过基类指针和引用来操作派生类数组。不过这根本就不是一个特性，因为这样的代码几乎从不如你所愿地那样运行。

多态和指针算法不能混合在一起来用，所以数组与多态也不能用在一起。值得注意的是如果你不从一个具体类（concrete classes）（例如BST）派生出另一个具体类（例如BalancedBST），那么你就不太可能犯这种使用多态性数组的错误。

## 4.避免无用的缺省构造函数

缺省构造函数（指没有参数的构造函数）在C++语言中是一种让你无中生有的方法。构造函数能初始化对象,而缺省构造函数则可以不利用任何在建立对象时的外部数据就能初始化对象。有时这样的方法是不错的。例如一些行为特性与数字相仿的对象被初始化为空值或不确定的值也是合理的，还有比如链表、哈希表、图等等数据结构也可以被初始化为空容器。

但不是所有的对象都属于上述类型，对于很多对象来说，不利用外部数据进行完全的初始化是不合理的。比如一个没有输入姓名的地址簿对象，就没有任何意义。在一个完美的世界里，无需任何数据即可建立对象的类可以包含缺省构造函数，而需要数据来建立对象的类则不能包含缺省构造函数。如果一个类没有缺省构造函数，就会存在一些使用上的限制。

考虑如下一个类，它表示公司设备，类包含一个公司的ID代码，这个ID代码被强制作为构造函数的参数：

```cpp
class EquipmentPiece {
public:
EquipmentPiece(int IDNumber);
...
};
```

因为EquipmentPiece类没有一个缺省构造函数，所以在三种情况下使用它，就会遇到问题。

1. 建立数组。一般来说，没有一种办法能在建立对象数组时给构造函数传递参数。所以在通常情况下，不可能建立EquipmentPiece对象数组：

```cpp
  EquipmentPiece bestPieces[10]; // 错误！没有正确调用 EquipmentPiece 构造函数
  EquipmentPiece *bestPieces = new EquipmentPiece[10]; // 错误！与上面的问题一样
```

有三种方法能回避开这个限制。具体参考Effective c++。

2.它们无法在许多基于模板（template-based）的容器类里使用。因为实例化一个模板时，模板的类型参数应该提供一个缺省构造函数，这是一个常见的要求。这个要求总是来自于模板内部，被建立的模板参数类型数组里。例如一个数组模板类：

```cpp
template<class T>
class Array {
public:
    Array(int size);
...
private:
    T *data;
};
template<class T>
Array<T>::Array(int size)
{
    data = new T[size]; // 为每个数组元素
    ... //依次调用 T::T()
}
```

在多数情况下，通过仔细设计模板可以杜绝对缺省构造函数的需求。例如标准的vector模板（生成一个类似于可扩展数组的类）对它的类型参数没有必须有缺省构造函数的要求。

3.在设计虚基类时所面临的要提供缺省构造函数还是不提供缺省构造函数的两难决策。不提供缺省构造函数的虚基类，很难与其进行合作。因为几乎所有的派生类在实例化时都必须给虚基类构造函数提供参数。这就要求所有由没有缺省构造函数的虚基类继承下来的派生类\(无论有多远\)都必须知道并理解提供给虚基类构造函数的参数的含义。派生类的作者是不会企盼和喜欢这种规定的。

4.谨慎定义数据类型转换函数

C＋＋编译器能够在两种数据类型之间进行隐式转换（implicit conversions）。有两种函数允许编译器进行这些的转换：单参数构造函数（single-argument constructors）和隐式类型转换运算符。单参数构造函数是指只用一个参数即可以调用的构造函数。该函数可以是只定义了一个参数，也可以是虽定义了多个参数但第一个参数以后的所有参数都有缺省值。以下有两个例子：

```cpp
class Name { // for names of things
public:
    Name(const string& s); // 转换 string 到 Name
...
};
class Rational { // 有理数类
public:
    Rational(int numerator = 0,int denominator = 1); // 转换int到有理数类
...
};
```

隐式类型转换运算符只是一个样子奇怪的成员函数：operator 关键字，其后跟一个类型符号。你不用定义函数的返回类型，因为返回类型就是这个函数的名字。例如为了允许Rational\(有理数\)类隐式地转换为double类型（在用有理数进行混合类型运算时，可能有用），你可以如此声明Rational类：

```cpp
class Rational {
public:
    ...
    operator double() const; // 转换Rational类成double类型
};
```

在下面这种情况下，这个函数会被自动调用：

```cpp
Rational r\(1, 2\); // r 的值是1/2

double d = 0.5 \* r; // 转换 r 到double,然后做乘法
```

以上这些说明只是一个复习，我真正想说的是为什么你不需要定义各种类型转换函数。根本问题是当你在不需要使用转换函数时，这些的函数缺却会被调用运行。结果，这些不正确的程序会做出一些令人恼火的事情，而你又很难判断出原因。

让我们首先分析一下隐式类型转换运算符，它们是最容易处理的。假设你有一个如上所述的Rational类，你想让该类拥有打印有理数对象的功能，就好像它是一个内置类型。因此，你可能会这么写：

```cpp
Rational r(1, 2);
cout << r; // 应该打印出"1/2"
```

再假设你忘了为Rational对象定义operator&lt;&lt;。你可能想打印操作将失败，因为没有合适的的operator&lt;&lt;被调用。但是你错了。当编译器调用operator&lt;&lt;时，会发现没有这样的函数存在，但是它会试图找到一个合适的隐式类型转换顺序以使得函数调用正常运行。类型转换顺序的规则定义是复杂的，但是在现在这种情况下，编译器会发现它们能调用Rational::operator double函数来把r转换为double类型。所以上述代码打印的结果是一个浮点数，而不是一个有理数。这简直是一个灾难，但是 \*\*它表明了隐式类型转换的缺点：它们的存在将导致错误的发生\*\* 。

解决方法是用不使用语法关键字的等同的函数来替代转换运算符。e.g.在库函数中的string类型没有包括隐式地从string转换成C风格的char\*的功能，而是定义了一个成员函数c\_str用来完成这个转换.

通过单参数构造函数进行隐式类型转换更难消除。而且在很多情况下这些函数所导致的问题要甚于隐式类型转换运算符。举一个例子，一个array类模板，这些数组需要调用者确定边界的上限与下限：

```cpp
template<class T>;
class Array {
public:
 Array(int lowBound, int highBound);
 Array(int size);
 T& operator[](int index);
...
};
```

第一个构造函数允许调用者确定数组索引的范围，例如从10到20。它是一个两参数构造函数，所以不能做为类型转换函数。第二个构造函数让调用者仅仅定义数组元素的个数（使用方法与内置数组的使用相似），不过不同的是它能做为类型转换函数使用，能导致无穷的痛苦。例如比较Array&lt;int&gt;对象，部分代码如下：

```cpp
bool operator==( const Array<int>& lhs,
const Array<int>& rhs);
Array<int> a(10);
Array<int> b(10);
...
for (int i = 0; i < 10; ++i)
if (a == b[i]) { // 哎呦! "a" 应该是 "a[i]"
do something for when
a[i] and b[i] are equal;
}
else {
 do something for when they're not;
}
```

我们想用a的每个元素与b的每个元素相比较，但是当录入a时，我们偶然忘记了数组下标。当然我们希望编译器能报出各种各样的警告信息，但是它根本没有。因为它把这个调用看成用Array&lt;int&gt;参数\(对于a\)和int\(对于b\[i\]\)参数调用operator==函数，然而没有operator==函数是这样的参数类型，我们的编译器注意到它能通过调用Array&lt;int&gt;构造函数能转换int类型到Array&lt;int&gt;类型，这个构造函数只有一个int类型的参数。然后编译器如此去编译，生成的代码就象这样：

```cpp
for (int i = 0; i < 10; ++i)
if (a == static_cast< Array<int> >(b[i])) ...
```

每一次循环都把a的内容与一个大小为b\[i\]的临时数组（内容是未定义的）比较。这不仅不可能以正确的方法运行，而且还是效率低下的。因为每一次循环我们都必须建立和释放Array&lt;int&gt;对象。

通过不声明运算符（operator）的方法,可以克服隐式类型转换运算符的缺点，但是单参数构造函数没有那么简单。毕竟，你确实想给调用者提供一个单参数构造函数。同时你也希望防止编译器不加鉴别地调用这个构造函数。幸运的是，有一个方法可以让你鱼肉与熊掌兼得。事实上是两个方法：一是容易的方法，二是当你的编译器不支持容易的方法时所必须使用的方法。

容易的方法是利用一个最新编译器的特性， explicit关键字。为了解决隐式类型转换而特别引入的这个特性，它的使用方法很好理解。构造函数用 explicit 声明，如果这样做，编译器会拒绝为了隐式类型转换而调用构造函数。显式类型转换依然合法。

另外一个方法是proxy class ，代理类。

## 6.自增\(increment\)、自减\(decrement\)操作符前缀形式与后缀形式的区别

```
C++规定后缀形式++ 有一个int类型参数。当函数被调用时，编译器传递一个0做为int参数的值给该函数：
```

```
class UPInt { // "unlimited precision int"
public:
UPInt& operator++(); // ++ 前缀
const UPInt operator++(int); // ++ 后缀
UPInt& operator--(); // -- 前缀
const UPInt operator--(int); // -- 后缀
UPInt& operator+=(int); // += 操作符，UPInts与ints 相运算
}；
UPInt i;
++i; // 调用 i.operator++();
i++; // 调用 i.operator++(0);
--i; // 调用 i.operator--();
i--; // 调用 i.operator--(0);
```

要注意的是：这些操作符前缀与后缀形式返回值类型是不同的。**前缀形式返回一个引用**，**后缀形式返回一个const类型**。下面我们将讨论`++`操作符的前缀与后缀形式，这些说明也同样适用于`--`操作符。

当处理用户定义的类型时，尽可能地使用前缀increment，因为它的效率较高。

## 7.不要重载“&&”,“\|\|”, 或“,”

不要重载以下操作符：

```cpp
.                 .*                 ::                 ?:
new             delete             sizeof            typeid
static_cast  dynamic_cast        const_cast      reinterpret_cast
```

能够重载：

```
operator new operator delete
operator new[] operator delete[]
+  -  *  /  %  ^  &  |  ~
!  =  <  >  +=  -=  *=  /=  %=
^=  &=  |=  <<  >>  >>=  <<=  ==  !=
<=  >=  &&  ||  ++  --  ,  ->*  ->
()  []
```

有关new和delete还有operator new, operator delete, operator new\[\], and operator delete\[\]的信息参见**8.**

## **8.理解各种不同含义的new和delete**

new操作符（new operator）和new操作（operator new）的区别：

`string *ps = new string("Memory Management");// new 为new操作符，跟sizeof一样是语言内置的`

new操作符要执行两个动作，一个是分配足够的空间，另一个是调用构造函数初始化内存中的对象。

new操作符为分配内存所调用函数的名字是operator new。函数operator new 通常这样声明：

`void * operator new(size_t size);`

返回值类型是`void*`，因为这个函数返回一个未经处理（raw）的指针，未初始化的内存。你一般不会直接调用operator new，但是一旦这么做，你可以象调用其它函数一样调用它：

`void *rawMemory = operator new(sizeof(string));`

操作符operator new将返回一个指针，指向一块足够容纳一个string类型对象的内存。  
就象malloc一样，operator new的职责只是分配内存。它对构造函数一无所知。operator new所了解的是内存分配。把operator new 返回的未经处理的指针传递给一个对象是new操作符的工作。

Deletion and Memory Deallocation

为了避免内存泄漏，每个动态内存分配必须与一个等同相反的deallocation对应。函数operator delete与delete操作符的关系与operator new与new操作符的关系一样。当你看到这些代码：

```cpp
string *ps;
...
delete ps;
```

你的编译器会生成代码来析构对象并释放对象占有的内存。

Operator delete用来释放内存，它被这样声明：

`void operator delete(void *memoryToBeDeallocated);`

因此，

`delete ps;`

导致编译器生成类似于这样的代码：

```
ps-> ~string;        //调用对象析构函数
operator delete(ps);    //删除对象占用内存
```

这有一个隐含的意思是如果你只想处理未被初始化的内存，你应该绕过new和delete操作符，而调用operator new 获得内存和operator delete释放内存给系统：

```
void* buffer = operator new(50*sizeof(char));   //分配足够多的内存以容纳50个char
...
operator delete(buffer);  //释放内存，没有调用析构函数
```

这与在C中调用malloc和free等同。

**Arrays**

```
string *ps = new string[10];
```

内存分配采用`operator new[ ]`，称为数组分配函数。它与`operator new`一样能被重载。

```
    另外，对于数组，在数组里的每一个对象的构造函数都必须被调用：
```

```cpp
string *ps = new string[10]; //调用operator new [] 为10个string 对象分配内存，然后对每个数组元素调用string对象的缺省构造函数
```

同样当delete操作符用于数组时，它为每个数组元素调用析构函数，然后调用operator delete来释放内存。

new和delete操作符是内置的，其行为不受你的控制，凡是它们调用的内存分配和释放函数则可以控制。当你想定制new和delete操作符的行为时，请记住你不能真的做到这一点。你只能改变它们为完成它们的功能所采取的方法，而它们所完成的功能则被语言固定下来，不能改变。





