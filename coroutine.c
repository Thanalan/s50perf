#include "coroutine.h"
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include "perf.h"

#if __APPLE__ && __MACH__
    #include <sys/ucontext.h>
#else 
    #include <ucontext.h>
#endif 

#define STACK_SIZE (1024*1024)
#define DEFAULT_COROUTINE 16

struct coroutine;

struct schedule {
    char stack[STACK_SIZE];
    ucontext_t main;
    int nco;
    int cap;
    int running;
    struct coroutine **co;
};

struct coroutine {
    coroutine_func func;
    void *ud;
    ucontext_t ctx;
    struct schedule * sch;
    ptrdiff_t cap;
    ptrdiff_t size;
    int status;
    char *stack;
};

struct coroutine * 
_co_new(struct schedule *S , coroutine_func func, void *ud) {
    struct coroutine * co = malloc(sizeof(*co));
    co->func = func;
    co->ud = ud;
    co->sch = S;
    co->cap = 0;
    co->size = 0;
    co->status = COROUTINE_READY;
    co->stack = NULL;
    return co;
}

void
_co_delete(struct coroutine *co) {
    free(co->stack);
    free(co);
}

struct schedule * 
coroutine_open(void) {
    struct schedule *S = malloc(sizeof(*S));
    S->nco = 0;
    S->cap = DEFAULT_COROUTINE;
    S->running = -1;
    S->co = malloc(sizeof(struct coroutine *) * S->cap);
    memset(S->co, 0, sizeof(struct coroutine *) * S->cap);
    return S;
}

void 
coroutine_close(struct schedule *S) {
    int i;
    for (i=0;i<S->cap;i++) {
        struct coroutine * co = S->co[i];
        if (co) {
            _co_delete(co);
        }
    }
    free(S->co);
    S->co = NULL;
    free(S);
}

int 
coroutine_new(struct schedule *S, coroutine_func func, void *ud) {
    struct coroutine *co = _co_new(S, func , ud);
    if (S->nco >= S->cap) {
        int id = S->cap;
        S->co = realloc(S->co, S->cap * 2 * sizeof(struct coroutine *));
        memset(S->co + S->cap , 0 , sizeof(struct coroutine *) * S->cap);
        S->co[S->cap] = co;
        S->cap *= 2;
        ++S->nco;
        return id;
    } else {
        int i;
        for (i=0;i<S->cap;i++) {
            int id = (i+S->nco) % S->cap;
            if (S->co[id] == NULL) {
                S->co[id] = co;
                ++S->nco;
                return id;
            }
        }
    }
    assert(0);
    return -1;
}

static void
mainfunc(uint32_t low32, uint32_t hi32) {
    uintptr_t ptr = (uintptr_t)low32 | ((uintptr_t)hi32 << 32);
    struct schedule *S = (struct schedule *)ptr;
    int id = S->running;
    struct coroutine *C = S->co[id];
    C->func(S,C->ud);
    _co_delete(C);
    S->co[id] = NULL;
    --S->nco;
    S->running = -1;
}

void 
coroutine_resume(struct schedule * S, int id) {
    assert(S->running == -1);
    assert(id >=0 && id < S->cap);
    struct coroutine *C = S->co[id];
    if (C == NULL)
        return;
    int status = C->status;
    switch(status) {
    case COROUTINE_READY:
        getcontext(&C->ctx);
        C->ctx.uc_stack.ss_sp = S->stack;
        C->ctx.uc_stack.ss_size = STACK_SIZE;
        C->ctx.uc_link = &S->main;
        S->running = id;
        C->status = COROUTINE_RUNNING;
        uintptr_t ptr = (uintptr_t)S;
        makecontext(&C->ctx, (void (*)(void)) mainfunc, 2, (uint32_t)ptr, (uint32_t)(ptr>>32));
        swapcontext(&S->main, &C->ctx);
        break;
    case COROUTINE_SUSPEND:
        memcpy(S->stack + STACK_SIZE - C->size, C->stack, C->size);
        S->running = id;
        C->status = COROUTINE_RUNNING;
        swapcontext(&S->main, &C->ctx);
        break;
    default:
        assert(0);
    }
}

static void
_save_stack(struct coroutine *C, char *top) {
    char dummy = 0;
    assert(top - &dummy <= STACK_SIZE);
    if (C->cap < top - &dummy) {
        free(C->stack);
        C->cap = top-&dummy;
        C->stack = malloc(C->cap);
    }
    C->size = top - &dummy;
    memcpy(C->stack, &dummy, C->size);
}

void
coroutine_yield(struct schedule * S) {
    int id = S->running;
    assert(id >= 0);
    struct coroutine * C = S->co[id];
    assert((char *)&C > S->stack);
    _save_stack(C,S->stack + STACK_SIZE);
    C->status = COROUTINE_SUSPEND;
    S->running = -1;
    swapcontext(&C->ctx , &S->main);
}

int 
coroutine_status(struct schedule * S, int id) {
    assert(id>=0 && id < S->cap);
    if (S->co[id] == NULL) {
        return COROUTINE_DEAD;
    }
    return S->co[id]->status;
}

int 
coroutine_running(struct schedule * S) {
    return S->running;
}

struct args {
    int n;
};

/*
int test_coroutine_hash_loop(void *args)
{
    loopargs_t *loopargs = args;

    if (NULL == args) {
        return 0;
    }
  	uint8_t *src = loopargs->buf;
	pce_queue_handle queue_handle = loopargs->queue_handle;
	//试验一下container_of,以后可以删去
	pce_queue_handle queue_handle1 = container_of(loopargs, thread_local_variables_t, loopargs);
	if(memcmp(queue_handle,queue_handle1)){
		printf("container_of_success\n");
	
	}	

	//完成信号量进行同步用，防止出队和出队对于的opdata不一致的情况
	struct COMPLETION_STRUCT complete; //初始化信号量

	COMPLETION_INIT(&complete);

    //<snippet name="completion">

   
	build_hash_cmd();

	//64是digest数组的长度，不是返回结果的长度。
	//PCE_HASH_SHA1类型未知
	//满足二级指针的要求


    enqueued_count = pce_enqueue(queue_handle, op_datas, 1);//入队一个
    	coroutine_yield(S); //发送完就退出当前执行情况
    
    if (0 == enqueued_count) {
         goto out;
    }
	
    i = 0;

	if (!COMPLETION_WAIT(&complete, TIMEOUT_MS))//等待完成
    {
        fprintf(stderr, "timeout or interruption in %s:%d\n",__func__ , __LINE__);
    }
            //</snippet>
    COMPLETION_DESTROY(&complete); //执行完成后销毁信号量
    //可以考虑使用条件变量进行同步
    out:
	//释放空间
	if (op_datas) {
		free(op_datas);
	}
	
	if (hash_datas) {
		free(hash_datas);
	}			
    return 1;
}


int run_coroutine(bench_function loop_function, loopargs_t *loopargs)
{
    int count, i;

    run = 1;
    count = 0;
	int async_jobs = 1;
	 struct args arg1 = { 0 };
    struct args arg2 = { 100 };
	int co[10];
	//创建协程
	struct schedule * S = coroutine_open();
	for(i = 0 ;i < async_jobs; i++)
		{
			co[i] = coroutine_new(S, loop_function,(void*)loopargs);

	}
    printf("main start\n");
	while(1){

		for(i = 0 ;i < async_jobs; i++){
			if(coroutine_status(S, co[i])){
				coroutine_resume(S, co[i]);
			}
		}

	}
   
    for (i = 0; run && i < 0x7fffffff; i++) {
		
        count += loop_function((void *)loopargs);
    }

	coroutine_close(S);
    return count;
}

*/
