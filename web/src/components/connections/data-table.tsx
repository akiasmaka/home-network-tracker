import { useState } from "react"
import type { ColumnDef, OnChangeFn, SortingState, VisibilityState } from "@tanstack/react-table"
import { flexRender, getCoreRowModel, useReactTable } from "@tanstack/react-table"

import { Button } from "@/components/ui/button"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"

type DataTableProps<TData> = {
    columns: ColumnDef<TData>[]
    data: TData[]
    onRowClick?: (row: TData) => void
    searchValue: string
    onSearchChange: (value: string) => void
    sorting: SortingState
    onSortingChange: OnChangeFn<SortingState>
    pageIndex: number
    pageCount: number
    onPageChange: (pageIndex: number) => void
}

export const DataTable = <TData,>({
    columns,
    data,
    onRowClick,
    searchValue,
    onSearchChange,
    sorting,
    onSortingChange,
    pageIndex,
    pageCount,
    onPageChange,
}: DataTableProps<TData>) => {
    const [columnVisibility, setColumnVisibility] = useState<VisibilityState>({})

    const table = useReactTable({
        data,
        columns,
        state: { sorting, columnVisibility },
        onSortingChange,
        onColumnVisibilityChange: setColumnVisibility,
        getCoreRowModel: getCoreRowModel(),
        manualSorting: true,
    })

    return (
        <div className="space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
                <Input
                    placeholder="Search connections..."
                    value={searchValue}
                    onChange={(event) => onSearchChange(event.target.value)}
                    className="max-w-xs"
                />
                <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                        <Button variant="outline" size="sm">
                            Columns
                        </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                        {table.getAllColumns().filter((column) => column.getCanHide()).map((column) => (
                            <DropdownMenuCheckboxItem
                                key={column.id}
                                checked={column.getIsVisible()}
                                onCheckedChange={(value) => column.toggleVisibility(Boolean(value))}
                            >
                                {column.id}
                            </DropdownMenuCheckboxItem>
                        ))}
                    </DropdownMenuContent>
                </DropdownMenu>
            </div>
            <div className="border border-border">
                <Table>
                    <TableHeader>
                        {table.getHeaderGroups().map((headerGroup) => (
                            <TableRow key={headerGroup.id}>
                                {headerGroup.headers.map((header) => (
                                    <TableHead key={header.id}>
                                        {header.isPlaceholder ? null : flexRender(header.column.columnDef.header, header.getContext())}
                                    </TableHead>
                                ))}
                            </TableRow>
                        ))}
                    </TableHeader>
                    <TableBody>
                        {table.getRowModel().rows.length ? (
                            table.getRowModel().rows.map((row) => (
                                <TableRow
                                    key={row.id}
                                    className={onRowClick ? "cursor-pointer" : undefined}
                                    onClick={() => onRowClick?.(row.original)}
                                >
                                    {row.getVisibleCells().map((cell) => (
                                        <TableCell key={cell.id}>{flexRender(cell.column.columnDef.cell, cell.getContext())}</TableCell>
                                    ))}
                                </TableRow>
                            ))
                        ) : (
                            <TableRow>
                                <TableCell colSpan={columns.length} className="text-center text-sm text-muted-foreground">
                                    No connections found.
                                </TableCell>
                            </TableRow>
                        )}
                    </TableBody>
                </Table>
            </div>
            <div className="flex items-center justify-between gap-2">
                <div className="text-xs text-muted-foreground">
                    Page {pageIndex + 1} of {Math.max(pageCount, 1)}
                </div>
                <div className="flex items-center gap-2">
                    <Button variant="outline" size="sm" onClick={() => onPageChange(pageIndex - 1)} disabled={pageIndex <= 0}>
                        Previous
                    </Button>
                    <Button
                        variant="outline"
                        size="sm"
                        onClick={() => onPageChange(pageIndex + 1)}
                        disabled={pageIndex >= Math.max(pageCount - 1, 0)}
                    >
                        Next
                    </Button>
                </div>
            </div>
        </div>
    )
}
