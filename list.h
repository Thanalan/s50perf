#ifndef _LIST_H
#define _LIST_H

typedef struct charlist {
    char **str;
    int len;
    int capacity;
	int dilatationCount;
	int dilatationSum;
}CharList;

typedef int boolean;//定义一个布尔类型
#define TRUE 1
#define FALSE 0

typedef int BOOL;//定义一个布尔类型


CharList *createCharList(int size);

//给集合添加值

void addCharList(CharList *pCharList, char *value) ;

//删除集合内指定的值

// 删除一个值
int deleteCharListByValue(CharList *pCharList, char *value);

//删除集合内指定下标的值
int deleteCharListByIndex(CharList *pCharList, int index);

//打印所有节点
void printCharList(CharList *pCharList);

//加工器
void forEachCharList(CharList *pCharList,char * (*func)(char *));

//查询指定元素的下标(第一个)

//查询指定元素的下标 ,没有找到返回-1
int charListIndexOf(CharList *pCharList, char *value);

//末尾查询指定元素下标(第一个)
int charListLastIndexOf(CharList *pCharList, char *value);

/**
 * 判断数组是否有序
 * @param pCharList
 * @param type  TRUE: 按照ASCII码排序   FALSE: 安装字符长度排序
 * @param isAsc  TRUE: 升序  FALSE: 降序
 * @return
 */
BOOL charListIsSorted(CharList *pCharList,BOOL type,BOOL isAsc);

//二分查询

/**
 * 二分查询,没有找到返回-1  以ASCII码查询
 * @param pCharList
 * @param value
 * @return  找到返回下标,没有找到返回-1
 */
int charListBinarySearch(CharList *pCharList, char *value);

//修改集合指定元素的值

//修改指定元素的值
void charListSet(CharList *pCharList, char *value, int index);

/**
 * 根据ASCII码排序,从小到大,或者根据长度排序,从小到大
 * @param pCharList
 * @param type   TRUE就是ASCII码排序, FALSE就是根据长度排序
 */
void charListSort(CharList *pCharList, boolean type);

 
//集合去重

void charListDistinct(CharList *pCharList);

//集合复制

//集合复制,返回新集合
CharList *charListCopy(CharList *pCharList);

//集合合并

//集合合并,返回新集合
CharList *charListMerge(CharList *pCharList1, CharList *pCharList2);

//记A，B是两个集合 ,A集合中不存在B集合的元素,那么A集合就是B集合的差集

//集合差集,返回新集合
CharList *charListDifference(CharList *pCharList1, CharList *pCharList2);

//对于两个给定集合A、B, 如果A集合中不存在B集合元素,那么B集合就是A集合的补集,当然反过来也可以说A集合是B集合的补集

//集合补集,返回新集合
CharList *charListComplement(CharList *pCharList1, CharList *pCharList2);

//对于两个给定集合A、B，由两个集合所有元素构成的集合,叫做A和B的并集。(需要去重只保留一个)

//集合并集,返回新集合
CharList *charListUnion(CharList *pCharList1, CharList *pCharList2);

//对于两个给定集合A、B，属于A又属于B的所有元素构成的集合，叫做A和B的交集。

//集合交集,返回新集合
CharList *charListIntersection(CharList *pCharList1, CharList *pCharList2);

//销毁集合

// 释放内存
void charListClean(CharList *pCharList);

//迭代器

// 迭代器结构
typedef struct charListIterator {
    CharList *charList;    // 迭代器所指向的集合
    int count;      // 迭代次数
} CharListIterator;

CharListIterator *createCharListIterator(CharList *charList);

boolean hasNextCharListIterator(CharListIterator *iterator);

//迭代下一个元素
char *nextCharListIterator(CharListIterator *iterator);

//使用迭代器演示:

//    CharList *pString = createCharList(10);
//    addCharList(pString, "100");
//    addCharList(pString, "huanmin2");
//    addCharList(pString, "huanmin3");
//    addCharList(pString, "huanmin5");
//    addCharList(pString, "1");
//    addCharList(pString, "23");
//    //迭代元素
//    CharListIterator *iterator = createCharListIterator(pString);
//    while (hasNextCharListIterator(iterator)) {
 //       char *p = nextCharListIterator(iterator);
 //       printf("%s\n", p);
 //   }
#endif

