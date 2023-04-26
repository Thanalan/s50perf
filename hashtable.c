#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hashtable.h"

//最好的char类型的hash算法,冲突较少,效率较高
static unsigned int BKDRHash(const char *str)
{
    unsigned int seed = 131;
    unsigned int hash = 0;

    while (*str)
    {
        hash = hash * seed + (*str++);
    }

    return (hash & 0x7FFFFFFF);
}

//hash值长度取模最后获取实际位置的下标
static  unsigned int default_hash_code(hash_map hashMap, const char * key){
    return BKDRHash(key)% hashMap.capacity;
}

hash_map *create_hash_map(int capacity) {
    //创建哈希表
    hash_map *hashMap= (hash_map *)malloc(sizeof(hash_map));
    //创建存储区域
    if(capacity<10){
        capacity=10;
    }
    hashMap->size=0;
    hashMap->dilatationCount=0;
    hashMap->dilatationSum=0;
    hashMap->nodeLen=0;
    hashMap->capacity=capacity;
    hashMap->list = (Entry **)calloc(capacity,sizeof(Entry));
    return hashMap;
}

//扩容基数
static int  expansion_base( hash_map *hashMap){
    int len = hashMap->capacity;
    int dilatationCount= hashMap->dilatationCount;
    hashMap->dilatationSum++;
    //基础扩容
    len+= (len>=100000000?len*0.2:
          len>=50000000?len*0.3:
          len>=10000000?len*0.4:
          len>=5000000?len*0.5:
          len>=1000000?len*0.6:
          len>=500000?len*0.7:
          len>=100000?len*0.8:
          len>=50000?len*0.9:
          len*1.0);
    hashMap->dilatationCount++;
    //频率扩容
    if(dilatationCount>=5){
        len+= (len>=100000000?len*1:
              len>=50000000?len*2:
              len>=10000000?len*3:
              len>=5000000?len*4:
              len>=1000000?len*5:
              len>=500000?len*6:
              len>=100000?len*7:
              len>=50000?len*8:
              len>=10000?len*9:
              len>=1000?len*10:
              len*20);
        hashMap->dilatationCount=0;
    }

    return len;
}

//扩容Map集合
static  void dilatation_hash(hash_map *hashMap){
    //原来的容量
    int capacity = hashMap->capacity;
    //扩容后的容量
    hashMap->capacity=expansion_base(hashMap);
    //节点长度清空
    hashMap->nodeLen=0;
    //创建新的存储区域
    Entry **newList=(Entry **)calloc(hashMap->capacity,sizeof(Entry));
    //遍历旧的存储区域,将旧的存储区域的数据拷贝到新的存储区域
    for(int i=0;i<capacity;i++){
        Entry *entry=hashMap->list[i];
        if(entry!=NULL){
            //获取新的存储区域的下标
            unsigned int newIndex=default_hash_code(*hashMap,entry->key);
            if(newList[newIndex]==NULL){
                Entry *newEntry = (Entry *)malloc(sizeof(Entry));
                newEntry->key = entry->key;
                newEntry->value = entry->value;
                newEntry->next = NULL;
                newList[newIndex] = newEntry;
                hashMap->nodeLen++;
            }else{//那么就是冲突链表添加链表节点
                Entry *newEntry = (Entry *)malloc(sizeof(Entry));
                newEntry->key = entry->key;
                newEntry->value = entry->value;
                //将新节点插入到链表头部(这样的好处是插入快,但是不能保证插入的顺序)
                newEntry->next = newList[newIndex];
                newList[newIndex] = newEntry;
            }
            //判断节点内链表是否为空
            if(entry->next!=NULL){
                //遍历链表,将链表节点插入到新的存储区域
                Entry *nextEntry=entry->next;
                while(nextEntry!=NULL){
                    //获取新的存储区域的下标
                    unsigned int newIndex=default_hash_code(*hashMap,nextEntry->key);
                    if(newList[newIndex]==NULL){
                        Entry *newEntry = (Entry *)malloc(sizeof(Entry));
                        newEntry->key = nextEntry->key;
                        newEntry->value = nextEntry->value;
                        newEntry->next = NULL;
                        newList[newIndex] = newEntry;
                        hashMap->nodeLen++;
                    }else{//那么就是冲突链表添加链表节点
                        Entry *newEntry = (Entry *)malloc(sizeof(Entry));
                        newEntry->key = nextEntry->key;
                        newEntry->value = nextEntry->value;
                        //将新节点插入到链表头部(这样的好处是插入快,但是不能保证插入的顺序)
                        newEntry->next = newList[newIndex];
                        newList[newIndex] = newEntry;
                    }
                    nextEntry=nextEntry->next;
                }
            }
        }
    }
    //释放旧的存储区域
    free(hashMap->list);
    //将新的存储区域赋值给旧的存储区域
    hashMap->list=newList;
}

//放入元素
void put_hash_map(hash_map *hashMap, char *key, void *value) {
    //判断是否需要扩容
    if(hashMap->nodeLen==hashMap->capacity){
        dilatation_hash(hashMap);
    }
    //获取hash值
    unsigned int hashCode = default_hash_code(*hashMap, key);
    //获取节点
    Entry *entry = hashMap->list[hashCode];

    //如果节点是空的那么直接添加
    if(entry==NULL){
        Entry *newEntry = (Entry *)malloc(sizeof(Entry));
        newEntry->key = key;
        newEntry->value = value;
        newEntry->next = NULL;
        hashMap->list[hashCode] = newEntry;
        hashMap->size++;
        hashMap->nodeLen++;
        return;
    }

    //判断是否存在该键,并且一样的话,更新值
    if(entry->key !=NULL && strcmp(entry->key,key)==0){
        entry->value = value;
        return;
    }
    // 当前节点不为空,而且key不一样,那么表示hash冲突了,需要添加到链表中
    //添加前需要先判断链表中是否存在该键
    while (entry != NULL) {
        //如果存在该键,那么更新值
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }
    //如果链表中不存在,那么就创建新的链表节点
    Entry *newEntry = (Entry *)malloc(sizeof(Entry));
    newEntry->key = key;
    newEntry->value = value;
    //将新节点插入到链表头部(这样的好处是插入快,但是不能保证插入的顺序)
    newEntry->next = hashMap->list[hashCode];
    hashMap->list[hashCode] = newEntry;
    hashMap->size++;

}

void print_hash_map(hash_map *hashMap) {
    for (int i = 0; i < hashMap->capacity; i++) {
        Entry *entry = hashMap->list[i];
        while (entry != NULL) {
            printf("%s:%p\n", entry->key, entry->value); //此处代码有修改
            //printf("%s:%s\n", entry->key, entry->value);
            entry = entry->next;
        }
    }
}

//获取Map集合中的指定元素
void *get_hash_map(hash_map *hashMap,const char *key) {
    //获取hash值
    unsigned int hashCode = default_hash_code(*hashMap, key);
    //获取节点
    Entry *entry = hashMap->list[hashCode];
    //如果节点是空的那么直接返回
    if(entry==NULL){
        return NULL;
    }
    //判断是否存在该键,并且一样的话,返回值
    if(entry->key !=NULL && strcmp(entry->key,key)==0){
        return entry->value;
    }
    // 当前节点不为空,而且key不一样,那么表示hash冲突了,需要查询链表
    while (entry != NULL) {
        //如果找到该键,那么返回值
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }
    return NULL;
}

//判断键是否存在
boolean contains_key(hash_map *hashMap, char *key) {
    //获取hash值
    unsigned int hashCode = default_hash_code(*hashMap, key);
    //获取节点
    Entry *entry = hashMap->list[hashCode];
    //如果节点是空的那么直接返回FALSE
    if(entry==NULL){
        return FALSE;
    }
    //判断是否存在该键,并且一样的话,返回TRUE
    if(entry->key !=NULL && strcmp(entry->key,key)==0){
        return TRUE;
    }
    // 当前节点不为空,而且key不一样,那么表示hash冲突了,需要查询链表
    while (entry != NULL) {
        //如果找到该键,那么返回TRUE
        if (strcmp(entry->key, key) == 0) {
            return TRUE;
        }
        entry = entry->next;
    }
    return FALSE;
}

//删除Map集合中的指定元素
void remove_hash_map(hash_map *hashMap, char *key) {
    //获取hash值
    unsigned int hashCode = default_hash_code(*hashMap, key);
    //获取节点
    Entry *entry = hashMap->list[hashCode];
    //如果节点是空的那么直接返回
    if(entry==NULL){
        return;
    }
    //判断是否存在该键,并且一样的话,删除该节点
    if(entry->key !=NULL && strcmp(entry->key,key)==0){
        hashMap->list[hashCode] = entry->next;
        free(entry);
        hashMap->size--;
        return;
    }
    // 当前节点不为空,而且key不一样,那么表示hash冲突了,需要查询链表
    while (entry != NULL) {
        //如果找到该键,那么删除该节点
        if (strcmp(entry->key, key) == 0) {
            Entry *next = entry->next;
            entry->next = next->next;
            free(next);
            hashMap->size--;
            return;
        }
        entry = entry->next;
    }
}

//修改Map集合中的指定元素

void update_hash_map(hash_map *hashMap, char *key, void *value) {
    //获取hash值
    unsigned int hashCode = default_hash_code(*hashMap, key);
    //获取节点
    Entry *entry = hashMap->list[hashCode];
    //如果节点是空的那么直接返回
    if(entry==NULL){
        return;
    }
    //判断是否存在该键,并且一样的话,修改该节点的值
    if(entry->key !=NULL && strcmp(entry->key,key)==0){
        entry->value = value;
        return;
    }
    // 当前节点不为空,而且key不一样,那么表示hash冲突了,需要查询链表
    while (entry != NULL) {
        //如果找到该键,那么修改该节点的值
        if (strcmp(entry->key, key) == 0) {
            entry->value = value;
            return;
        }
        entry = entry->next;
    }
}
//
//迭代器
#if 0
hash_mapIterator *create_hash_map_iterator(hash_map *hashMap){
    hash_mapIterator *hashMapIterator= malloc(sizeof(hash_mapIterator));;
    hashMapIterator->hashMap = hashMap;
    hashMapIterator->count= 0;//迭代次数
    hashMapIterator->index= 0;//迭代位置
    hashMapIterator->nextEntry= NULL;//下次迭代节点

    return hashMapIterator;
}

boolean has_next_hash_map_iterator(hash_mapIterator *iterator){
    return iterator->count < iterator->hashMap->size ? TRUE : FALSE;
}

Entry *next_hash_map_iterator(hash_mapIterator *iterator) {
    if (has_next_hash_map_iterator(iterator)) {
        //如果节点中存在hash冲突链表那么就迭代链表
        if(iterator->nextEntry!=NULL){//如果下次迭代节点不为空,那么直接返回下次迭代节点
            Entry *entry = iterator->nextEntry;
            iterator->nextEntry = entry->next;
            iterator->count++;
            return entry;
        }

        Entry *pEntry1 = iterator->hashMap->list[iterator->index];
        //找到不是空的节点
        while (pEntry1==NULL){
            pEntry1 = iterator->hashMap->list[++iterator->index];
        }
        //如果没有hash冲突节点,那么下次迭代节点在当前节点向后继续搜索
        if(pEntry1->next==NULL){
            Entry *pEntry2= iterator->hashMap->list[++iterator->index];
            while (pEntry2==NULL){
                pEntry2 = iterator->hashMap->list[++iterator->index];
            }
            iterator->nextEntry =pEntry2;
        }else{
            iterator->nextEntry = pEntry1->next;
        }
        iterator->count++;
        return pEntry1;
    }
    return  NULL;
}

//获取所有的key

//需要借助我之前文件写的List集合,有兴趣的可以去看看

//获取所有的key ,返回一个自定义的List集合
CharList *get_keys(hash_map *hashMap){

    CharList *pCharlist = createCharList(10);
    hash_mapIterator *pIterator = create_hash_map_iterator(hashMap);
    while (has_next_hash_map_iterator(pIterator)) {
        Entry *entry = next_hash_map_iterator(pIterator);
        addCharList(pCharlist,entry->key); //此处代码有修改
        //addCharList(&pCharlist,entry->key); //此处代码有修改
    }
    return pCharlist;
}

//获取所有的value

//获取所有的value,返回一个自定义的List集合
CharList *get_values(hash_map *hashMap){
    CharList *pCharlist = createCharList(10);
    hash_mapIterator *pIterator = create_hash_map_iterator(hashMap);
    while (has_next_hash_map_iterator(pIterator)) {
        Entry *entry = next_hash_map_iterator(pIterator);
        addCharList(pCharlist,entry->value);
	//addCharList(&pCharlist,entry->key); //此处代码有修改
    }
    return pCharlist;
}

//复制一个Map

hash_map *copy_hash_map(hash_map *hashMap){
    hash_map *phash_map = create_hash_map(hashMap->capacity);
    hash_mapIterator *pIterator = create_hash_map_iterator(hashMap);
    while (has_next_hash_map_iterator(pIterator)) {
        Entry *entry = next_hash_map_iterator(pIterator);
        put_hash_map(phash_map,entry->key,entry->value);
    }
    return phash_map;
}

//将一个map集合合并到另一个map集合里

//将一个map集合,合并到另一个map集合里   hashMap2合并到hashMap1
void merge_hash_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_mapIterator *pIterator = create_hash_map_iterator(hashMap2);
    while (has_next_hash_map_iterator(pIterator)) {
        Entry *entry = next_hash_map_iterator(pIterator);
        put_hash_map(hashMap1,entry->key,entry->value);
    }
}

//合并两个Map集合,返回一个新的Map集合

hash_map *merge_hash_map_new_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_map *phash_map = create_hash_map(hashMap1->capacity+hashMap2->capacity);
    hash_mapIterator *pIterator1 = create_hash_map_iterator(hashMap1);
    while (has_next_hash_map_iterator(pIterator1)) {
        Entry *entry = next_hash_map_iterator(pIterator1);
        put_hash_map(phash_map,entry->key,entry->value);
    }
    hash_mapIterator *pIterator2 = create_hash_map_iterator(hashMap2);
    while (has_next_hash_map_iterator(pIterator2)) {
        Entry *entry = next_hash_map_iterator(pIterator2);
        put_hash_map(phash_map,entry->key,entry->value);
    }
    return phash_map;
}

//差集

//差集,返回一个新的Map集合,返回hashMap2的差集
hash_map *difference_hash_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_map *phash_map = create_hash_map(hashMap1->capacity);
    hash_mapIterator *pIterator1 = create_hash_map_iterator(hashMap1);
    while (has_next_hash_map_iterator(pIterator1)) {
        Entry *entry = next_hash_map_iterator(pIterator1);
        if(!contains_key(hashMap2,entry->key)){
            put_hash_map(phash_map,entry->key,entry->value);
        }
    }
    return phash_map;
}

//交集

//交集,返回一个新的Map集合
hash_map *intersection_hash_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_map *phash_map = create_hash_map(hashMap1->capacity);
    hash_mapIterator *pIterator1 = create_hash_map_iterator(hashMap1);
    while (has_next_hash_map_iterator(pIterator1)) {
        Entry *entry = next_hash_map_iterator(pIterator1);
        if(contains_key(hashMap2,entry->key)){
            put_hash_map(phash_map,entry->key,entry->value);
        }
    }
    return phash_map;
}

//补集

//补集,返回一个新的Map集合
hash_map *complement_hash_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_map *phash_map = create_hash_map(hashMap1->capacity);
    hash_mapIterator *pIterator1 = create_hash_map_iterator(hashMap1);
    while (has_next_hash_map_iterator(pIterator1)) {
        Entry *entry = next_hash_map_iterator(pIterator1);
        if(!contains_key(hashMap2,entry->key)){
            put_hash_map(phash_map,entry->key,entry->value);
        }
    }
    hash_mapIterator *pIterator2 = create_hash_map_iterator(hashMap2);
    while (has_next_hash_map_iterator(pIterator2)) {
        Entry *entry = next_hash_map_iterator(pIterator2);
        if(!contains_key(hashMap1,entry->key)){
            put_hash_map(phash_map,entry->key,entry->value);
        }
    }
    return phash_map;
}

//并集
hash_map *union_hash_map(hash_map *hashMap1,hash_map *hashMap2){
    hash_map *phash_map = create_hash_map(hashMap1->capacity+hashMap2->capacity);
    hash_mapIterator *pIterator1 = create_hash_map_iterator(hashMap1);
    while (has_next_hash_map_iterator(pIterator1)) {
        Entry *entry = next_hash_map_iterator(pIterator1);
        put_hash_map(phash_map,entry->key,entry->value);
    }
    hash_mapIterator *pIterator2 = create_hash_map_iterator(hashMap2);
    while (has_next_hash_map_iterator(pIterator2)) {
        Entry *entry = next_hash_map_iterator(pIterator2);
        put_hash_map(phash_map,entry->key,entry->value);
    }
    return phash_map;
}
#endif

//清除Map
void hash_map_clear(hash_map *hashMap){
    for (int i = 0; i < hashMap->nodeLen; i++) {
        // 释放冲突值内存
        Entry *entry = hashMap->list[i];
        if(entry!=NULL){
            Entry *nextEntry = entry->next;
            while (nextEntry != NULL) {
                Entry *next = nextEntry->next;
                free(nextEntry);
                nextEntry = next;
            }
            free(entry);
        }
    }
    // 释放存储空间
    free(hashMap->list);
    free(hashMap);
}



