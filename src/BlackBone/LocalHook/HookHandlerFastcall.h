#pragma once

namespace blackbone
{

template <typename T, typename U, typename... Args>
static constexpr int __fastcall
FastCallToIntel(T&&__ecx, U&&__edx, Args&&... args) {
    constexpr auto arg_count = sizeof...(Args);
    static_assert (arg_count > 0, "use fastcall instead");

    constexpr size_t stack_count = (arg_count > 2) ? arg_count : (0);

    auto pDetour = (DetourBase*)((_NT_TIB*)NtCurrentTeb())->ArbitraryUserPointer;

    auto old_edi = pDetour->_context.edi;
    auto old_esi = pDetour->_context.esi;

    auto _callOriginal = pDetour->_callOriginal;

    INT res = NULL;

    __asm {
        //int 3
        mov ecx, stack_count

    next_arg:
        cmp ecx, 2
        jle no_args

        dec ecx
        push [ebp+ecx*4 + 8]

        jmp next_arg

    no_args:
        mov ecx, __ecx
        mov edx, __edx
        mov edi, old_edi
        mov esi, old_esi

        call _callOriginal
        mov res, eax
    }

    return res;
}

template<typename R, typename... Args, class C, bool is_intel>
struct HookHandler<R( __fastcall* )(Args...), C, is_intel> : public DetourBase
{
    using ReturnType = std::conditional_t<std::is_same_v<R, void>, int, R>;

    using type    = R( __fastcall* )(Args...);
    using hktype  = R( __fastcall* )(Args&...);
    using hktypeC = R( C::* )(Args&...);

    //
    // Workaround for void return type
    //
    using typeR    = ReturnType( __fastcall* )(Args...);
    using hktypeR  = ReturnType( __fastcall* )(Args&...);
    using hktypeCR = ReturnType( C::* )(Args&...);

    static constexpr std::size_t arg_count = sizeof...(Args);

    static __declspec(noinline) ReturnType __fastcall Handler( Args... args )
    {
        HookHandler* pInst = (HookHandler*)((_NT_TIB*)NtCurrentTeb())->ArbitraryUserPointer;
        return pInst->HandlerP(std::forward<Args>( args )... );
    }

    ReturnType HandlerP(Args&&... args )
    {
        ReturnType val_new, val_original;

        DisableHook();

        if (_order == CallOrder::HookFirst)
        {
            val_new = CallCallback( std::forward<Args>( args )... );
            val_original = CallOriginal( std::forward<Args>( args )... );
        }
        else if (_order == CallOrder::HookLast)
        {
            val_original = CallOriginal( std::forward<Args>( args )... );
            val_new = CallCallback( std::forward<Args>( args )... );
        }
        else
        {
            val_original = val_new = CallCallback( std::forward<Args>( args )... );
        }

        if (this->_hooked)
            EnableHook();

        return (_retType == ReturnMethod::UseOriginal ? val_original : val_new);
    }

    inline ReturnType CallOriginal( Args&&... args )
    {
        /**
        * This is an attempt to use custom calling convention which is missing in the current compiler
        * 
        * ECX, EDX, EDI, ESI, stack
        * 
        * Refer to:
        * https://www.intel.com/content/www/us/en/develop/documentation/cpp-compiler-developer-guide-and-reference/top/compiler-reference/c-c-calling-conventions.html
        */
        //if constexpr (is_intel && ArgCount > 2)
        if constexpr (is_intel)
        {
            //Sleep(5000);
            //__debugbreak();

            //return FastCallToIntel(args...);
            return (reinterpret_cast<typeR>(&FastCallToIntel))(args...);
        }
        return (reinterpret_cast<typeR>(_callOriginal))(args...);
    }

    inline ReturnType CallCallback( Args&&... args )
    {
        if (_callbackClass != nullptr)
            return ((C*)_callbackClass->*brutal_cast<hktypeCR>(_callback))(args...);
        else
            return (reinterpret_cast<hktypeR>(_callback))(args...);
    }

    const auto& GetSavedContext() const {
        return _context;
    }
};

}