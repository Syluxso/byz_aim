package com.nyberg.iam.web;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.*;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v1/admin/db")
public class DbViewerController {

    private static final String SCHEMA = "iam";
    private final JdbcTemplate jdbc;

    public DbViewerController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/tables")
    public List<String> tables() {
        return jdbc.queryForList(
                "SELECT table_name FROM information_schema.tables " +
                "WHERE table_schema = ? AND table_type = 'BASE TABLE' " +
                "ORDER BY table_name",
                String.class, SCHEMA);
    }

    @GetMapping("/tables/{table}")
    public Map<String, Object> tableData(
            @PathVariable String table,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "100") int size) {

        List<String> valid = tables();
        if (!valid.contains(table)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Unknown table");
        }

        String quoted = "\"" + SCHEMA + "\".\"" + table + "\"";
        int offset = page * size;

        List<String> columns = jdbc.queryForList(
                "SELECT column_name FROM information_schema.columns " +
                "WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position",
                String.class, SCHEMA, table);

        List<Map<String, Object>> rawRows = jdbc.queryForList(
                "SELECT * FROM " + quoted + " ORDER BY 1 LIMIT ? OFFSET ?", size, offset);

        List<List<String>> rows = rawRows.stream()
                .map(row -> columns.stream()
                        .map(col -> {
                            Object val = row.get(col);
                            return val != null ? val.toString() : null;
                        })
                        .collect(Collectors.toList()))
                .collect(Collectors.toList());

        Long total = jdbc.queryForObject("SELECT COUNT(*) FROM " + quoted, Long.class);

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("columns", columns);
        result.put("rows", rows);
        result.put("total", total != null ? total : 0L);
        result.put("page", page);
        result.put("size", size);
        return result;
    }
}
