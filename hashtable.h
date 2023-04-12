#ifndef HASHTABLE_H
#define HASHTABLE_h

#include "list.h"
typedef struct entry {
    char * key;             // 键
    void * value;           // 值
    struct entry * next;    // 冲突链表
} Entry;

typedef int boolean;//定义一个布尔类型
#define TRUE 1
#define FALSE 0
// 哈希表结构体
typedef struct hashMap {
    int size;           // 集合元素个数
    int capacity;       // 容量
    int nodeLen;       //节点长度
    Entry **list;         // 存储区域
    int dilatationCount;  //扩容次数
    int dilatationSum;  //扩容总次数

} HashMap;

// 迭代器结构
typedef struct hashMapIterator {
    Entry *nextEntry;// 迭代器当前指向
    int count;//迭代次数
    HashMap *hashMap;
    int index; //位置
}HashMapIterator;

//创建
HashMap *createHashMap(int capacity);

//放入key-value元素
void putHashMap(HashMap * hashMap, char * key, void * value);

//打印hashtable
void printHashMap(HashMap *hashMap);


//获取Map集合中的指定元素
void *getHashMap(HashMap *hashMap, const char *key);

//判断键是否存在
boolean containsKey(HashMap *hashMap, char *key);

//删除Map集合中的指定元素
void removeHashMap(HashMap *hashMap, char *key);

//修改Map集合中的指定元素

void updateHashMap(HashMap *hashMap, char *key, void *value);

//迭代器
HashMapIterator *createHashMapIterator(HashMap *hashMap);

boolean hasNextHashMapIterator(HashMapIterator *iterator);

Entry *nextHashMapIterator(HashMapIterator *iterator);

//获取所有的key ,返回一个自定义的List集合
CharList *getKeys(HashMap *hashMap);

//获取所有的value,返回一个自定义的List集合
CharList *getValues(HashMap *hashMap);

//复制一个Map

HashMap *copyHashMap(HashMap *hashMap);

//将一个map集合,合并到另一个map集合里   hashMap2合并到hashMap1
void mergeHashMap(HashMap *hashMap1,HashMap *hashMap2);

//合并两个Map集合,返回一个新的Map集合
HashMap *mergeHashMapNewMap(HashMap *hashMap1,HashMap *hashMap2);

//差集,返回一个新的Map集合,返回hashMap2的差集
HashMap *differenceHashMap(HashMap *hashMap1,HashMap *hashMap2);

//交集,返回一个新的Map集合
HashMap *intersectionHashMap(HashMap *hashMap1,HashMap *hashMap2);

//补集,返回一个新的Map集合
HashMap *complementHashMap(HashMap *hashMap1,HashMap *hashMap2);

//并集
HashMap *unionHashMap(HashMap *hashMap1,HashMap *hashMap2);

//清除Map
void hashMapClear(HashMap *hashMap);



#endif
