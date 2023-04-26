#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "hashtable.h"
#include "list.h"

//list的c语言实现，用法参考c++ stl

//创建一个空节点, 可以指定容量默认为10
CharList *createCharList(int size) {
    if (size < 10) {
        size = 10;
    }
    //初始化结构体和一个2级指针
    CharList *charList = (CharList *) calloc(1, sizeof(CharList));
    charList->str= (char **) calloc(size, sizeof(char *));
    charList->len = 0;
    charList->capacity = size;
    return charList;
}

//扩容基数
static int  expansionBase( CharList *charList){
    int len = charList->capacity;
    int dilatationCount= charList->dilatationCount;
    charList->dilatationSum++;
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
    charList->dilatationCount++;
    //频率扩容
    if(dilatationCount>=3){
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
        charList->dilatationCount=0;
    }

    return len;
}

static void  dilatation(CharList *pCharList) {
    CharList *charList = pCharList;
    //int capacity1 =charList->capacity;//获取当前节点的容积
    int size =expansionBase(pCharList);//容积增加
    charList->capacity= size;//更新容积
    char **p1 = (char **) realloc(charList->str,size*sizeof(char *));
    charList->str=p1;
}

//给集合添加值

void addCharList(CharList *pCharList, char *value) {
    CharList *charList = pCharList;
    int len1 = charList->len;//获取当前节点的长度
    int capacity1 =charList->capacity;//获取数组的容量
    if (len1 == capacity1) {
        dilatation(pCharList);//扩容
    }
    charList->str[len1] = value;//插入数据
    charList->len++;
}

 //删除集合内指定的值

// 删除一个值
int deleteCharListByValue(CharList *pCharList, char *value) {
    CharList *charList = pCharList;
    int len1 = charList->len;//获取当前节点的长度
    for (int i = 0; i < len1; ++i) {
        if (strcmp(charList->str[i],value)==0) {//找到了
            for (int j = i; j < len1 - 1; ++j) {//后面的节点向前移动
                charList->str[j] = charList->str[j + 1];
            }
            //去除结尾的元素
            pCharList->str[len1 - 1]=NULL;
            charList->len--;
            return 1;
        }
    }

    return -1;
}
//
//删除集合内指定下标的值

//删除集合内指定下标的值
int deleteCharListByIndex(CharList *pCharList, int index) {
    CharList *charList =pCharList;
    int len1 = charList->len;//获取当前节点的长度
    if (index < 0 || index >= len1) {
        return -1;
    }
    for (int j = index; j < len1 - 1; ++j) {//后面的节点向前移动
        charList->str[j] = charList->str[j + 1];
    }
    //去除结尾的元素
    pCharList->str[len1 - 1]=NULL;
    charList->len--;
    return 1;
}

//打印集合

//打印所有节点
void printCharList(CharList *pCharList) {
    int len1 = pCharList->len;
    for (int i = 0; i < len1; i++) {
        printf("%s\n", pCharList->str[i]);
    }
}

//加工器

//加工器
void forEachCharList(CharList *pCharList,char * (*func)(char *)) {
    int len1 = pCharList->len;
    for (int i = 0; i < len1; i++) {
        pCharList->str[i]=func(pCharList->str[i]);
    }
}

 
//查询指定元素的下标(第一个)

//查询指定元素的下标 ,没有找到返回-1
int charListIndexOf(CharList *pCharList, char *value) {
    int len1 =  pCharList->len;
    for (int i = 0; i < len1; i++) {
        if (strcmp(pCharList->str[i],value)==0) {
            return i;
        }
    }
    return -1;
}



//末尾查询指定元素下标(第一个)

int charListLastIndexOf(CharList *pCharList, char *value) {
    int len1 =  pCharList->len;
    for (int i = len1 - 1; i >= 0; i--) {
        if (strcmp(pCharList->str[i],value)==0) {
            return i;
        }
    }
    return -1;
}



//判断数组是否有序


/**
 * 判断数组是否有序
 * @param pCharList
 * @param type  TRUE: 按照ASCII码排序   FALSE: 安装字符长度排序
 * @param isAsc  TRUE: 升序  FALSE: 降序
 * @return
 */
BOOL charListIsSorted(CharList *pCharList,BOOL type,BOOL isAsc) {
    int len1 = pCharList->len;
    BOOL result=TRUE; //返回结果
    if(type){//按照ASCII码排序方式进行判断

        if(isAsc){
            //从小到大
            for (int i = 0; i < len1 - 1; i++) {
                if (strcmp(pCharList->str[i],pCharList->str[i + 1])>0) {
                    result=FALSE;
                    break;
                }
            }
        }else{
            //从大到小
            for (int i = 0; i < len1 - 1; i++) {
                if (strcmp(pCharList->str[i],pCharList->str[i + 1])<0) {
                    result=FALSE;
                    break;
                }
            }
        }

    }else{
        if(isAsc){
            //从小到大
            for (int i = 0; i < len1 - 1; i++) {
                if (strlen(pCharList->str[i])>strlen(pCharList->str[i + 1])) {
                    result=FALSE;
                    break;
                }
            }
        }else{
            //从大到小
            for (int i = 0; i < len1 - 1; i++) {
                if (strlen(pCharList->str[i])<strlen(pCharList->str[i + 1])) {
                    result=FALSE;
                    break;
                }
            }
        }
    }

    return result;
}

  
//二分查询

/**
 * 二分查询,没有找到返回-1  以ASCII码查询
 * @param pCharList
 * @param value
 * @return  找到返回下标,没有找到返回-1
 */
int charListBinarySearch(CharList *pCharList, char *value) {
    if(!charListIsSorted(pCharList,TRUE,TRUE)){ //判断是否是排序的数组,如果不是那么我们给排序
        //二分查询需要是有序的数组,所以需要先排序 以ASCII码进行排序
        charListSort(pCharList,1);
    }
    int len1 =  pCharList->len;
    int low = 0;
    int high = len1 - 1;
    while (low <= high) {
        int mid = (low + high) / 2;//中间下标
        if (strcmp(pCharList->str[mid],value)==0) {//找到了
            return mid;
        }
        if (strcmp(pCharList->str[mid],value)>0) {//中间值比查找值大
            high = mid - 1;//向左找
        } else {//比中间值比差值值小
            low = mid + 1;//向右找
        }
    }
    return -1;
}

   

//修改集合指定元素的值

//修改指定元素的值
void charListSet(CharList *pCharList, char *value, int index) {
    int len1 =  pCharList->len;
    if (index < 0 || index >= len1) {
        return;
    }
    pCharList->str[index] = value;
}



//快速排序

//快速排序 (根据ASCII码排序,从小到大)
static void quickSort(char **str, int left, int right) {
    if (left >= right) {
        return;
    }
    char *p = str[left];
    int i = left;
    int j = right;
    while (i < j) {
        while (i < j && strcmp(str[j],p)>=0) {
            j--;
        }
        str[i] = str[j];
        while (i < j && strcmp(str[i],p)<=0) {
            i++;
        }
        str[j] = str[i];
    }
    str[i] = p;
    quickSort(str, left, i - 1);
    quickSort(str, i + 1, right);
}

//快速排序(根据长度排序,从小到大)
static void quickSortByLen(char **str, int left, int right) {
    if (left >= right) {
        return;
    }
    char *p = str[left];
    int i = left;
    int j = right;
    while (i < j) {
        while (i < j && strlen(str[j])>=strlen(p)) {
            j--;
        }
        str[i] = str[j];
        while (i < j && strlen(str[i])<=strlen(p)) {
            i++;
        }
        str[j] = str[i];
    }
    str[i] = p;
    quickSortByLen(str, left, i - 1);
    quickSortByLen(str, i + 1, right);
}
/**
 * 根据ASCII码排序,从小到大,或者根据长度排序,从小到大
 * @param pCharList
 * @param type   TRUE就是ASCII码排序, FALSE就是根据长度排序
 */
void charListSort(CharList *pCharList, boolean type) {
    if(type){
        quickSort(pCharList->str, 0, pCharList->len-1);
    }else{
        quickSortByLen(pCharList->str, 0, pCharList->len-1);
    }
}

 
//集合去重

void charListDistinct(CharList *pCharList) {
    int len1 = pCharList->len;
    for (int i = 0; i < len1; i++) {
        for (int j = i + 1; j < len1; j++) {
            if (strcmp(pCharList->str[i],pCharList->str[j])==0) {
                for (int k = j; k < len1 - 1; ++k) {//将后面的内容向前移动
                    pCharList->str[k] = pCharList->str[k + 1];
                }
                //去除结尾的元素
                pCharList->str[len1 - 1]=NULL;
                len1--;
                pCharList->len--;//长度减1
                j--;//重新比较
            }
        }
    }
}

 
//集合复制

//集合复制,返回新集合
CharList *charListCopy(CharList *pCharList) {
    int len1 = pCharList->len;
    CharList *pNewCharList = createCharList(len1);
    for (int i = 0; i < len1; i++) {
        char *p = pCharList->str[i];
        addCharList(pNewCharList, p);
    }
    return pNewCharList;
}

 

//集合合并

//集合合并,返回新集合
CharList *charListMerge(CharList *pCharList1, CharList *pCharList2) {
    int len1 = pCharList1->len;
    int len2 = pCharList2->len;
    CharList *pNewCharList = createCharList(len1 + len2);
    for (int i = 0; i < len1; i++) {
        char *p = pCharList1->str[i];
        addCharList(pNewCharList, p);
    }
    for (int i = 0; i < len2; i++) {
        char *p = pCharList2->str[i];
        addCharList(pNewCharList, p);
    }
    return pNewCharList;
}

 

//集合差集

//在这里插入图片描述
//记A，B是两个集合 ,A集合中不存在B集合的元素,那么A集合就是B集合的差集

//集合差集,返回新集合
CharList *charListDifference(CharList *pCharList1, CharList *pCharList2) {
    int len1 = pCharList1->len;
    int len2 = pCharList2->len;
    CharList *pNewCharList = charListCopy(pCharList1);
    for (int i = 0; i < len2; i++) {
        int index = charListIndexOf(pNewCharList, pCharList2->str[i]);
        if (index != -1) {
            free(pNewCharList->str[index]);//释放内存
            for (int j = index; j < len1 - 1; ++j) {//将后面的内容向前移动
                pNewCharList->str[j] = pNewCharList->str[j + 1];
            }
            //去除结尾的元素
            pNewCharList->str[len1 - 1]=NULL;
            len1--;
            pNewCharList->len--;//长度减1
            i--;//重新比较
        }
    }
    return pNewCharList;
}

  
//集合补集

//对于两个给定集合A、B, 如果A集合中不存在B集合元素,那么B集合就是A集合的补集,当然反过来也可以说A集合是B集合的补集

//集合补集,返回新集合
CharList *charListComplement(CharList *pCharList1, CharList *pCharList2) {
    CharList *pCharlist1 = charListDifference(pCharList1, pCharList2);
    CharList *pCharlist2 = charListDifference(pCharList2, pCharList1);
    CharList *pCharlist = charListMerge(pCharlist1, pCharlist2);
    return pCharlist;
}

//集合并集

//对于两个给定集合A、B，由两个集合所有元素构成的集合,叫做A和B的并集。(需要去重只保留一个)

//集合并集,返回新集合
CharList *charListUnion(CharList *pCharList1, CharList *pCharList2) {
    CharList *pCharlist1 = charListDifference(pCharList1, pCharList2);
    CharList *pCharlist2 = charListMerge(pCharlist1, pCharList2);
    return pCharlist2;
}


//集合交集


//对于两个给定集合A、B，属于A又属于B的所有元素构成的集合，叫做A和B的交集。

//集合交集,返回新集合
CharList *charListIntersection(CharList *pCharList1, CharList *pCharList2) {
    int len2 = pCharList2->len;
    CharList *pNewCharList = createCharList(len2/2);
    for (int i = 0; i < len2; ++i){
        int of = charListIndexOf(pCharList1, pCharList2->str[i]);
        if(of!=-1){
            addCharList(pNewCharList, pCharList2->str[i]);
        }
    }
    return pNewCharList;
}



//销毁集合

// 释放内存
void charListClean(CharList *pCharList) {
    //清除集合
    free(pCharList->str);
    pCharList->str= NULL;
    pCharList->len = 0;
    pCharList->capacity = 0;
    pCharList->dilatationCount = 0;
    pCharList->dilatationSum = 0;
    //清除结构体
    free(pCharList);
}

//迭代器


CharListIterator *createCharListIterator(CharList *charList) {
    CharListIterator *iterator = malloc(sizeof(CharListIterator));
    iterator->charList = charList;
    iterator->count = 0;
    return iterator;
}
boolean hasNextCharListIterator(CharListIterator *iterator) {
    boolean b = iterator->count < iterator->charList->len ? TRUE : FALSE;
    if(!b){//迭代完毕释放内存
        free(iterator);
    }
    return b;
}
//迭代下一个元素
char *nextCharListIterator(CharListIterator *iterator) {
    if(!hasNextCharListIterator(iterator)){
        return NULL;
    }
    char *p = iterator->charList->str[iterator->count];
    iterator->count++;
    return p;
}

 

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




