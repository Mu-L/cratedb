package io.crate.planner.optimizer.costs;

import org.elasticsearch.test.IntegTestCase;

import io.crate.testing.UseHashJoins;
import io.crate.testing.UseRandomizedOptimizerRules;

public class PlanStatsIT  extends IntegTestCase {


    @UseHashJoins(1)
    @UseRandomizedOptimizerRules(0)
    public void test_foo() {
        for(int i = 1; i <= 10; i++) {
            var st = String.format("CREATE TABLE t%s(a%s INTEGER PRIMARY KEY, b%s INTEGER,  x%s STRING)", i, i, i, i);
            execute(st);
        }

        execute("INSERT INTO t1 VALUES(1,1,'table t1 row 1')");
        execute("INSERT INTO t1 VALUES(2,3,'table t1 row 2')");
        execute("INSERT INTO t1 VALUES(3,7,'table t1 row 3')");
        execute("INSERT INTO t1 VALUES(4,9,'table t1 row 4')");
        execute("INSERT INTO t1 VALUES(5,5,'table t1 row 5')");
        execute("INSERT INTO t1 VALUES(6,4,'table t1 row 6')");
        execute("INSERT INTO t1 VALUES(7,10,'table t1 row 7')");
        execute("INSERT INTO t1 VALUES(8,8,'table t1 row 8')");
        execute("INSERT INTO t1 VALUES(9,6,'table t1 row 9')");
        execute("INSERT INTO t1 VALUES(10,2,'table t1 row 10')");

        execute("INSERT INTO t2 VALUES(1,7,'table t2 row 1')");
        execute("INSERT INTO t2 VALUES(2,9,'table t2 row 2')");
        execute("INSERT INTO t2 VALUES(3,6,'table t2 row 3')");
        execute("INSERT INTO t2 VALUES(4,3,'table t2 row 4')");
        execute("INSERT INTO t2 VALUES(5,5,'table t2 row 5')");
        execute("INSERT INTO t2 VALUES(6,4,'table t2 row 6')");
        execute("INSERT INTO t2 VALUES(7,1,'table t2 row 7')");
        execute("INSERT INTO t2 VALUES(8,10,'table t2 row 8')");
        execute("INSERT INTO t2 VALUES(9,8,'table t2 row 9')");
        execute("INSERT INTO t2 VALUES(10,2,'table t2 row 10')");

        execute("INSERT INTO t3 VALUES(1,6,'table t3 row 1')");
        execute("INSERT INTO t3 VALUES(2,1,'table t3 row 2')");
        execute("INSERT INTO t3 VALUES(3,3,'table t3 row 3')");
        execute("INSERT INTO t3 VALUES(4,2,'table t3 row 4')");
        execute("INSERT INTO t3 VALUES(5,9,'table t3 row 5')");
        execute("INSERT INTO t3 VALUES(6,5,'table t3 row 6')");
        execute("INSERT INTO t3 VALUES(7,8,'table t3 row 7')");
        execute("INSERT INTO t3 VALUES(8,7,'table t3 row 8')");
        execute("INSERT INTO t3 VALUES(9,10,'table t3 row 9')");
        execute("INSERT INTO t3 VALUES(10,4,'table t3 row 10')");

        execute("INSERT INTO t4 VALUES(1,7,'table t4 row 1')");
        execute("INSERT INTO t4 VALUES(2,2,'table t4 row 2')");
        execute("INSERT INTO t4 VALUES(3,3,'table t4 row 3')");
        execute("INSERT INTO t4 VALUES(4,1,'table t4 row 4')");
        execute("INSERT INTO t4 VALUES(5,4,'table t4 row 5')");
        execute("INSERT INTO t4 VALUES(6,5,'table t4 row 6')");
        execute("INSERT INTO t4 VALUES(7,8,'table t4 row 7')");
        execute("INSERT INTO t4 VALUES(8,9,'table t4 row 8')");
        execute("INSERT INTO t4 VALUES(9,6,'table t4 row 9')");
        execute("INSERT INTO t4 VALUES(10,10,'table t4 row 10')");

        execute("INSERT INTO t5 VALUES(1,10,'table t5 row 1')");
        execute("INSERT INTO t5 VALUES(2,3,'table t5 row 2')");
        execute("INSERT INTO t5 VALUES(3,7,'table t5 row 3')");
        execute("INSERT INTO t5 VALUES(4,6,'table t5 row 4')");
        execute("INSERT INTO t5 VALUES(5,8,'table t5 row 5')");
        execute("INSERT INTO t5 VALUES(6,2,'table t5 row 6')");
        execute("INSERT INTO t5 VALUES(7,5,'table t5 row 7')");
        execute("INSERT INTO t5 VALUES(8,9,'table t5 row 8')");
        execute("INSERT INTO t5 VALUES(9,1,'table t5 row 9')");
        execute("INSERT INTO t5 VALUES(10,4,'table t5 row 10')");

        execute("INSERT INTO t6 VALUES(1,2,'table t6 row 1')");
        execute("INSERT INTO t6 VALUES(2,3,'table t6 row 2')");
        execute("INSERT INTO t6 VALUES(3,8,'table t6 row 3')");
        execute("INSERT INTO t6 VALUES(4,5,'table t6 row 4')");
        execute("INSERT INTO t6 VALUES(5,10,'table t6 row 5')");
        execute("INSERT INTO t6 VALUES(6,6,'table t6 row 6')");
        execute("INSERT INTO t6 VALUES(7,4,'table t6 row 7')");
        execute("INSERT INTO t6 VALUES(8,1,'table t6 row 8')");
        execute("INSERT INTO t6 VALUES(9,9,'table t6 row 9')");
        execute("INSERT INTO t6 VALUES(10,7,'table t6 row 10')");

        execute("INSERT INTO t7 VALUES(1,1,'table t7 row 1')");
        execute("INSERT INTO t7 VALUES(2,5,'table t7 row 2')");
        execute("INSERT INTO t7 VALUES(3,3,'table t7 row 3')");
        execute("INSERT INTO t7 VALUES(4,9,'table t7 row 4')");
        execute("INSERT INTO t7 VALUES(5,8,'table t7 row 5')");
        execute("INSERT INTO t7 VALUES(6,4,'table t7 row 6')");
        execute("INSERT INTO t7 VALUES(7,2,'table t7 row 7')");
        execute("INSERT INTO t7 VALUES(8,10,'table t7 row 8')");
        execute("INSERT INTO t7 VALUES(9,6,'table t7 row 9')");
        execute("INSERT INTO t7 VALUES(10,7,'table t7 row 10')");

        execute("INSERT INTO t8 VALUES(1,8,'table t8 row 1')");
        execute("INSERT INTO t8 VALUES(2,3,'table t8 row 2')");
        execute("INSERT INTO t8 VALUES(3,6,'table t8 row 3')");
        execute("INSERT INTO t8 VALUES(4,7,'table t8 row 4')");
        execute("INSERT INTO t8 VALUES(5,4,'table t8 row 5')");
        execute("INSERT INTO t8 VALUES(6,2,'table t8 row 6')");
        execute("INSERT INTO t8 VALUES(7,10,'table t8 row 7')");
        execute("INSERT INTO t8 VALUES(8,9,'table t8 row 8')");
        execute("INSERT INTO t8 VALUES(9,5,'table t8 row 9')");
        execute("INSERT INTO t8 VALUES(10,1,'table t8 row 10')");

        execute("INSERT INTO t9 VALUES(1,4,'table t9 row 1')");
        execute("INSERT INTO t9 VALUES(2,2,'table t9 row 2')");
        execute("INSERT INTO t9 VALUES(3,6,'table t9 row 3')");
        execute("INSERT INTO t9 VALUES(4,10,'table t9 row 4')");
        execute("INSERT INTO t9 VALUES(5,9,'table t9 row 5')");
        execute("INSERT INTO t9 VALUES(6,1,'table t9 row 6')");
        execute("INSERT INTO t9 VALUES(7,5,'table t9 row 7')");
        execute("INSERT INTO t9 VALUES(8,7,'table t9 row 8')");
        execute("INSERT INTO t9 VALUES(9,8,'table t9 row 9')");
        execute("INSERT INTO t9 VALUES(10,3,'table t9 row 10')");

        execute("INSERT INTO t10 VALUES(1,10,'table t10 row 1')");
        execute("INSERT INTO t10 VALUES(2,3,'table t10 row 2')");
        execute("INSERT INTO t10 VALUES(3,2,'table t10 row 3')");
        execute("INSERT INTO t10 VALUES(4,8,'table t10 row 4')");
        execute("INSERT INTO t10 VALUES(5,4,'table t10 row 5')");
        execute("INSERT INTO t10 VALUES(6,1,'table t10 row 6')");
        execute("INSERT INTO t10 VALUES(7,5,'table t10 row 7')");
        execute("INSERT INTO t10 VALUES(8,6,'table t10 row 8')");
        execute("INSERT INTO t10 VALUES(9,7,'table t10 row 9')");
        execute("INSERT INTO t10 VALUES(10,9,'table t10 row 10')");

        execute("REFRESH TABLE t1, t2, t3, t4, t5, t6, t7, t8, t9, t10");
        execute("ANALYZE");

        var query = "SELECT * FROM t1,t2,t3,t4,t5,t6,t7,t8,t9,t10 WHERE a7=9 AND a6=b1 AND b6=a5 AND b8=a1 AND a9=b2 AND a2=b5 AND b3=a7 AND a10=b9 AND a3=b10 AND b4=a8";
        execute(query);
        System.out.println(response);

    }
}
