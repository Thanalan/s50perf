#ifndef HASHTABLE_H
#define HASHTABLE_h

//#include "list.h"
typedef struct entry {
    char * key;             // 键
    void * value;           // 值
    struct entry * next;    // 冲突链表
} Entry;

typedef int boolean;//定义一个布尔类型
#define TRUE 1
#define FALSE 0
// 哈希表结构体
typedef struct{
    int size;           // 集合元素个数
    int capacity;       // 容量
    int nodeLen;       //节点长度
    Entry **list;         // 存储区域
    int dilatationCount;  //扩容次数
    int dilatationSum;  //扩容总次数

} hash_map;
#if 0
// 迭代器结构
typedef struct hashMapIterator {
    Entry *nextEntry;// 迭代器当前指向
    int count;//迭代次数
    hash_map *hashMap;
    int index; //位置
}hash_mapIterator;
#endif
//创建
hash_map *create_hash_map(int capacity);

//放入key-value元素
void put_hash_map(hash_map * hashMap, char * key, void * value);

//打印hashtable
void print_hash_map(hash_map *hashMap);


//获取Map集合中的指定元素
void *get_hash_map(hash_map *hashMap, const char *key);

//判断键是否存在
boolean contains_key(hash_map *hashMap, char *key);

//删除Map集合中的指定元素
void remove_hash_map(hash_map *hashMap, char *key);

//修改Map集合中的指定元素

void update_hash_map(hash_map *hashMap, char *key, void *value);

#if 0
//迭代器
hash_mapIterator *create_hash_map_iterator(hash_map *hashMap);

boolean has_next_hash_map_iterator(hash_mapIterator *iterator);

Entry *next_hash_map_iterator(hash_mapIterator *iterator);

//获取所有的key ,返回一个自定义的List集合
CharList *get_keys(hash_map *hashMap);

//获取所有的value,返回一个自定义的List集合
CharList *get_values(hash_map *hashMap);

//复制一个Map

hash_map *copy_hash_map(hash_map *hashMap);

//将一个map集合,合并到另一个map集合里   hashMap2合并到hashMap1
void merge_hash_map(hash_map *hashMap1,hash_map *hashMap2);

//合并两个Map集合,返回一个新的Map集合
hash_map *merge_hash_map_new_map(hash_map *hashMap1,hash_map *hashMap2);

//差集,返回一个新的Map集合,返回hashMap2的差集
hash_map *difference_hash_map(hash_map *hashMap1,hash_map *hashMap2);

//交集,返回一个新的Map集合
hash_map *intersection_hash_map(hash_map *hashMap1,hash_map *hashMap2);

//补集,返回一个新的Map集合
hash_map *complement_hash_map(hash_map *hashMap1,hash_map *hashMap2);

//并集
hash_map *union_hash_map(hash_map *hashMap1,hash_map *hashMap2);
#endif
//清除Map
void hash_map_clear(hash_map *hashMap);



#endif
