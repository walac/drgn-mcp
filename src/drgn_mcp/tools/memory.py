import drgn

from drgn_mcp._app import mcp
from drgn_mcp.state import state


@mcp.tool()
def read_memory(address: int | str, size: int = 64) -> str:
    """Read raw memory at the given address and return a hex dump.

    DIFFERENCE FROM read_typed_memory: read_memory returns a raw hex dump
    with ASCII representation. Prefer read_typed_memory when you know the
    underlying data type (e.g., u64, c_string).

    Args:
        address: The memory address to read from. Can be an integer or hex string.
        size: Number of bytes to read. Maximum is 4096 bytes.

    Returns:
        A multi-line hex dump showing address, hex bytes, and ASCII
        representation (16 bytes per line).

    Examples:
        read_memory("0xffffffff81000000", size=128)
        read_memory(0xffffffff81000000)
    """
    prog = state.require_loaded()
    addr = address if isinstance(address, int) else int(address, 0)
    size = min(size, 4096)
    data = prog.read(addr, size)
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr + offset:#018x}  {hex_part:<48s}  {ascii_part}")
    return "\n".join(lines)


@mcp.tool()
def get_dmesg() -> str:
    """Retrieve the kernel log buffer (dmesg output).

    Use this to read the kernel logs leading up to the crash.

    Returns:
        A multi-line string containing timestamped kernel log messages.
        Truncates from the front at 8KB, keeping the most recent messages.
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.printk import get_printk_records

    lines = [
        f"[{r.timestamp.total_seconds():>12.6f}] {r.text}"
        for r in get_printk_records(prog)
    ]
    output = "\n".join(lines)

    max_len = 8000
    if len(output) > max_len:
        return f"... (truncated, {len(output)} total chars)\n{output[-max_len:]}"
    return output


@mcp.tool()
def search_memory(
    pattern: str,
    search_type: str = "bytes",
    alignment: int = 1,
    limit: int = 10,
) -> str:
    """Search all program memory for specific strings, integers, or regular expressions.

    Use this to find addresses containing specific data when you know the value but not
    the exact memory location. The required format for pattern strictly depends on
    the search_type.

    Args:
        pattern: The value to search for. Format rules based on search_type:
            - "bytes": A plain text string that will be UTF-8 encoded (e.g., "swapper").
              Do NOT pass space-separated hex bytes.
            - "u32", "u64", "word": A valid Python integer literal string (e.g., "0xdeadbeef" or "42").
            - "regex": A regular expression string that will be evaluated as a byte regex.
        search_type: The type of data to search for. Must be "bytes", "u32", "u64", "word", or "regex".
        alignment: Memory alignment for "bytes" searches (e.g., 8 for 64-bit aligned). Ignored for other types.
        limit: Maximum number of matches to return.

    Returns:
        A multi-line string of matches (one per line). Format depends on search_type:
        - "bytes": Hex addresses only.
        - "u32", "u64", "word": "address: value" pairs.
        - "regex": "address: matched_bytes_repr".
        Returns "No matches found" if empty. Appends a truncation notice if matches exceed limit.

    Examples:
        search_memory("swapper", search_type="bytes")
        search_memory("0xdeadbeef", search_type="u32", alignment=4)
        search_memory("42", search_type="u64", alignment=8)
        search_memory("panic.*", search_type="regex")
    """
    prog = state.require_loaded()

    lines = []
    count = 0

    try:
        match search_type:
            case "bytes":
                for addr in prog.search_memory(
                    pattern.encode(), alignment=alignment
                ):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}")
                    count += 1
            case "u32" | "u64" | "word":
                value = int(pattern, 0)
                search_fn = getattr(prog, f"search_memory_{search_type}")
                for addr, found in search_fn(value):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}: {found:#x}")
                    count += 1
            case "regex":
                for addr, match_bytes in prog.search_memory_regex(
                    pattern.encode()
                ):
                    if count >= limit:
                        break
                    lines.append(f"{addr:#x}: {match_bytes!r}")
                    count += 1
            case _:
                return (
                    f"Unknown search type '{search_type}'. "
                    "Use: bytes, u32, u64, word, regex."
                )
    except drgn.FaultError as e:
        return f"Memory fault during search: {e}"
    except ValueError as e:
        return f"Invalid pattern: {e}"

    if not lines:
        return "No matches found"

    output = "\n".join(lines)
    if count >= limit:
        output += f"\n... (limited to {limit} results, use higher limit to see more)"
    return output


@mcp.tool()
def get_source_location(address: int | str) -> str:
    """Map a code address or symbol to its exact C source code location (file, line, column).

    Similar to 'addr2line'. Use this to find exactly where in the source code an instruction
    pointer or function address belongs. It automatically resolves and displays the full
    inline function chain if the address falls within inlined code.

    Args:
        address: A numeric address (e.g., 0xffffffff81000000), a hex address string
                 (e.g., "0xffffffff81000000"), or a "symbol+offset" string (e.g., "schedule+0x15").

    Returns:
        A string showing the exact source file, line, and column.
        For inlined code, returns a multi-line call chain from innermost to outermost
        (e.g., "#0 inner_func at file.c:10" followed by "#1 outer_func at file.c:20").
        Returns an error message if the location cannot be resolved.

    Examples:
        get_source_location(0xffffffff823ab120)
        get_source_location("panic+0x50")
    """
    prog = state.require_loaded()

    try:
        return str(prog.source_location(address))
    except LookupError:
        return f"No source location found for '{address}'"
    except drgn.FaultError as e:
        return f"Memory fault resolving '{address}': {e}"


@mcp.tool()
def read_typed_memory(
    address: int | str,
    value_type: str = "u64",
    count: int = 1,
    physical: bool = False,
) -> str:
    """Read and format specific data types from memory.

    Prefer this over read_memory when you know the underlying data type (e.g., reading an
    array of pointers or a C string). It formats the output natively rather than returning
    a raw hex dump.

    Args:
        address: Starting memory address as integer or hex string.
        value_type: The type of data to read. Must be one of: "u8", "u16", "u32", "u64",
                    "word" (pointer size), or "c_string".
        count: Number of consecutive elements to read (ignored if value_type is "c_string").
        physical: If True, treat the address as a physical memory address instead of virtual.

    Returns:
        The formatted memory contents based on value_type:
        - Integer types: Multi-line string of "address: value" pairs (addresses are
          0x-prefixed and padded to 18 characters; values are hex).
        - "c_string": The decoded text string directly.
        Returns an error message if the type is unknown or memory is inaccessible.

    Examples:
        read_typed_memory("0xffff888100000000", value_type="c_string")
        read_typed_memory(0xffffffff82000000, value_type="u64", count=4)
    """
    prog = state.require_loaded()
    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match value_type:
            case "c_string":
                data = prog.read_c_string(addr, physical, max_size=8000)
                return data.decode(errors="replace")
            case "u8" | "u16" | "u32" | "u64" | "word":
                read_fn = getattr(prog, f"read_{value_type}")
                type_sizes: dict[str, int] = {
                    "u8": 1, "u16": 2, "u32": 4, "u64": 8,
                    "word": prog.address_size(),
                }
                size = type_sizes[value_type]
                count = min(count, 256)

                lines = []
                for i in range(count):
                    value = read_fn(addr + i * size, physical)
                    lines.append(f"{addr + i * size:#018x}: {value:#x}")
                return "\n".join(lines)
            case _:
                return (
                    f"Unknown type '{value_type}'. "
                    "Use: u8, u16, u32, u64, word, c_string."
                )
    except drgn.FaultError as e:
        return f"Memory fault at {addr:#x}: {e}"


@mcp.tool()
def translate_address(
    address: int | str,
    direction: str = "virt_to_phys",
) -> str:
    """Translate a memory address between virtual, physical, page, and PFN forms.

    Use this to convert between different kernel address representations. All
    translations operate on directly mapped (linear) addresses.

    Args:
        address: The address or PFN to translate, as integer or hex string.
        direction: The translation to perform. Must be one of:
            - "virt_to_phys": virtual address to physical address
            - "phys_to_virt": physical address to virtual address
            - "virt_to_page": virtual address to struct page pointer
            - "page_to_virt": page pointer to virtual address
            - "page_to_pfn": page pointer to page frame number
            - "pfn_to_page": page frame number to struct page pointer
            - "virt_to_pfn": virtual address to page frame number

    Returns:
        The translated address in hex format, or an error message if the
        translation fails (e.g., address not in direct map).

    Examples:
        translate_address(0xffff888100000000, "virt_to_phys")
        translate_address("0x100000", direction="phys_to_virt")
        translate_address(0xffff888100000000, "virt_to_pfn")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import (
        page_to_pfn,
        page_to_virt,
        pfn_to_page,
        phys_to_virt,
        virt_to_page,
        virt_to_pfn,
        virt_to_phys,
    )

    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match direction:
            case "virt_to_phys":
                result = virt_to_phys(prog, addr)
            case "phys_to_virt":
                result = phys_to_virt(prog, addr)
            case "virt_to_page":
                result = virt_to_page(prog, addr)
            case "page_to_virt":
                result = page_to_virt(prog.object("struct page *", addr))
            case "page_to_pfn":
                result = page_to_pfn(prog.object("struct page *", addr))
            case "pfn_to_page":
                result = pfn_to_page(prog, addr)
            case "virt_to_pfn":
                result = virt_to_pfn(prog, addr)
            case _:
                return (
                    f"Unknown direction '{direction}'. Use: virt_to_phys, "
                    "phys_to_virt, virt_to_page, page_to_virt, page_to_pfn, "
                    "pfn_to_page, virt_to_pfn."
                )
        return str(result)
    except drgn.FaultError as e:
        return f"Translation failed: {e}"


@mcp.tool()
def get_page_info(
    address: int | str,
    source: str = "virt",
) -> str:
    """Get detailed information about a memory page.

    Use this to inspect page flags, compound page status, and slab membership
    for a given page. Useful for diagnosing memory corruption or understanding
    page state at crash time.

    Args:
        address: The address or PFN identifying the page.
        source: How to interpret the address. Must be one of:
            - "virt": address is a virtual address (default)
            - "pfn": address is a page frame number

    Returns:
        A multi-line string showing page flags (decoded), compound page info,
        slab membership, and page address. Returns an error message if the
        page cannot be resolved.

    Examples:
        get_page_info(0xffff888100000000)
        get_page_info(256, source="pfn")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import (
        PageCompound,
        PageSlab,
        compound_order,
        decode_page_flags,
        pfn_to_page,
        virt_to_page,
    )

    addr = address if isinstance(address, int) else int(address, 0)

    try:
        match source:
            case "virt":
                page = virt_to_page(prog, addr)
            case "pfn":
                page = pfn_to_page(prog, addr)
            case _:
                return f"Unknown source '{source}'. Use: virt, pfn."

        lines = [f"Page: {page}"]
        lines.append(f"Flags: {decode_page_flags(page)}")
        lines.append(f"Slab: {PageSlab(page)}")
        is_compound = PageCompound(page)
        lines.append(f"Compound: {is_compound}")
        if is_compound:
            lines.append(f"Compound order: {compound_order(page).value_()}")
        return "\n".join(lines)
    except drgn.FaultError as e:
        return f"Cannot access page at {addr:#x}: {e}"


@mcp.tool()
def get_slab_info(cache_name: str = "") -> str:
    """Get information about kernel slab caches.

    Use this to inspect the slab allocator's state, either listing all caches
    with usage statistics or showing details for a specific cache by name.

    Args:
        cache_name: Optional name of a specific slab cache to inspect
            (e.g., "task_struct", "kmalloc-256"). If empty, lists all caches
            with summary usage stats.

    Returns:
        If cache_name is empty: a multi-line summary of all slab caches with
        object counts and slab counts.
        If cache_name is provided: detailed usage for that specific cache.
        Returns an error message if the named cache is not found.

    Examples:
        get_slab_info()
        get_slab_info("task_struct")
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.slab import (
        find_slab_cache,
        for_each_slab_cache,
        slab_cache_usage,
        slab_total_usage,
    )

    if cache_name:
        cache = find_slab_cache(prog, cache_name)
        if cache is None:
            return f"No slab cache found with name '{cache_name}'"
        usage = slab_cache_usage(cache)
        name = cache.name.string_().decode()
        return (
            f"Cache: {name}\n"
            f"Object size: {cache.size.value_()}\n"
            f"Slabs: {usage.num_slabs}\n"
            f"Objects: {usage.num_objs}\n"
            f"Free objects: {usage.free_objs}"
        )

    lines = []
    try:
        total = slab_total_usage(prog)
        lines.append(
            f"Total slab pages: reclaimable={total.reclaimable_pages}, "
            f"unreclaimable={total.unreclaimable_pages}"
        )
    except drgn.FaultError as e:
        lines.append(f"Total slab pages: <error: {e}>")
    lines.append("")
    for cache in for_each_slab_cache(prog):
        name = cache.name.string_().decode()
        try:
            usage = slab_cache_usage(cache)
            lines.append(
                f"{name}: {usage.num_objs} objs, "
                f"{usage.free_objs} free, {usage.num_slabs} slabs"
            )
        except drgn.FaultError:
            lines.append(f"{name}: <error reading usage>")
    return "\n".join(lines)


@mcp.tool()
def get_vma_info(
    pid: int,
    address: int | str | None = None,
    limit: int = 100,
) -> str:
    """Inspect virtual memory areas (VMAs) for a kernel task.

    Use this to list all VMAs in a process's address space, or find the
    specific VMA containing a given address. Useful for diagnosing page
    faults, memory mapping issues, or understanding process memory layout.

    Args:
        pid: The PID of the task whose VMAs to inspect.
        address: Optional address to find the containing VMA. If not provided,
            lists all VMAs for the task.
        limit: Maximum number of VMAs to return when listing all (default 100).

    Returns:
        If address is not provided: a multi-line listing of all VMAs showing
        start, end, and name/path for each.
        If address is provided: details of the VMA containing that address,
        or a message if no VMA contains it.
        Returns an error if the task or its mm_struct is not found.

    Examples:
        get_vma_info(1)
        get_vma_info(1234, address=0x7f0000000000)
    """
    prog = state.require_loaded()
    from drgn.helpers.linux.mm import for_each_vma, vma_find, vma_name
    from drgn.helpers.linux.pid import find_task as _find_task

    task = _find_task(prog, pid)
    if task is None:
        return f"No task found with PID {pid}"

    mm = task.mm.read_()
    if not mm:
        return f"Task {pid} has no mm_struct (kernel thread?)"

    if address is not None:
        addr = address if isinstance(address, int) else int(address, 0)
        vma = vma_find(mm, addr)
        if not vma:
            return f"No VMA contains address {addr:#x} in task {pid}"
        name = vma_name(vma).decode(errors="replace")
        return (
            f"VMA: {vma.vm_start.value_():#x}-{vma.vm_end.value_():#x}\n"
            f"Name: {name}\n"
            f"Flags: {vma.vm_flags.value_():#x}"
        )

    lines = []
    count = 0
    for vma in for_each_vma(mm):
        if count >= limit:
            lines.append(f"... (limited to {limit} VMAs)")
            break
        start = vma.vm_start.value_()
        end = vma.vm_end.value_()
        name = vma_name(vma).decode(errors="replace")
        lines.append(f"{start:#x}-{end:#x} {name}")
        count += 1

    return "\n".join(lines) if lines else "No VMAs found"
