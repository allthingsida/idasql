#include <gtest/gtest.h>

#include "session_handler.hpp"

using idasql::SessionHandler;

TEST(SessionHandlerSafeName, AcceptsValidNames) {
    EXPECT_TRUE(SessionHandler::is_safe_table_name("funcs"));
    EXPECT_TRUE(SessionHandler::is_safe_table_name("A1_b2"));
    EXPECT_TRUE(SessionHandler::is_safe_table_name(std::string(128, 'a')));
}

TEST(SessionHandlerSafeName, RejectsInvalidNames) {
    EXPECT_FALSE(SessionHandler::is_safe_table_name(""));
    EXPECT_FALSE(SessionHandler::is_safe_table_name("bad-name"));
    EXPECT_FALSE(SessionHandler::is_safe_table_name("with space"));
    EXPECT_FALSE(SessionHandler::is_safe_table_name("semi;colon"));
    EXPECT_FALSE(SessionHandler::is_safe_table_name(std::string(129, 'a')));
}

TEST(SessionHandlerCallbacks, SchemaRejectsInvalidName) {
    std::string executed_sql;
    SessionHandler sh(
        [&](const std::string& sql) -> std::string {
            executed_sql = sql;
            return "ok";
        },
        /*enable_claude=*/false
    );

    std::string result = sh.callbacks().get_schema("bad-name");
    EXPECT_EQ(result, "Invalid table name");
    EXPECT_TRUE(executed_sql.empty());
}

TEST(SessionHandlerCallbacks, SchemaExecutesValidName) {
    std::string executed_sql;
    SessionHandler sh(
        [&](const std::string& sql) -> std::string {
            executed_sql = sql;
            return "ok";
        },
        /*enable_claude=*/false
    );

    std::string result = sh.callbacks().get_schema("funcs");
    EXPECT_EQ(result, "ok");
    EXPECT_FALSE(executed_sql.empty());
    EXPECT_NE(executed_sql.find("sqlite_master"), std::string::npos);
    EXPECT_NE(executed_sql.find("funcs"), std::string::npos);
}
