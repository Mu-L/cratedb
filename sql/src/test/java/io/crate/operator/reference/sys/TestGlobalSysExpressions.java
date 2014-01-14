package io.crate.operator.reference.sys;

import io.crate.metadata.MetaDataModule;
import io.crate.metadata.ReferenceIdent;
import io.crate.metadata.ReferenceResolver;
import io.crate.metadata.TableIdent;
import io.crate.metadata.sys.SysExpression;
import io.crate.metadata.sys.SystemReferences;
import io.crate.operator.Input;
import org.elasticsearch.common.inject.AbstractModule;
import org.elasticsearch.common.inject.Injector;
import org.elasticsearch.common.inject.ModulesBuilder;
import org.elasticsearch.common.settings.ImmutableSettings;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.monitor.os.OsService;
import org.elasticsearch.monitor.os.OsStats;
import org.junit.Before;
import org.junit.Test;

import java.util.Map;

import static junit.framework.Assert.assertNull;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TestGlobalSysExpressions {

    private Injector injector;
    private ReferenceResolver resolver;

    class TestModule extends AbstractModule {

        @Override
        protected void configure() {
            bind(Settings.class).toInstance(ImmutableSettings.EMPTY);

            OsService osService = mock(OsService.class);
            OsStats osStats = mock(OsStats.class);
            when(osService.stats()).thenReturn(osStats);
            when(osStats.loadAverage()).thenReturn(new double[]{1, 5, 15});
            bind(OsService.class).toInstance(osService);
        }
    }

    @Before
    public void setUp() throws Exception {
        injector = new ModulesBuilder().add(
                new TestModule(),
                new MetaDataModule(),
                new SysExpressionModule()
        ).createInjector();
        resolver = injector.getInstance(ReferenceResolver.class);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testWrongSchema() throws Exception {
        // unsupported schema
        ReferenceIdent ident = new ReferenceIdent(new TableIdent("something", "sometable"), "somecolumn");
        resolver.getInfo(ident);

    }


    @Test
    public void testInfoLookup() throws Exception {

        ReferenceIdent ident = NodeLoadExpression.INFO_LOAD.ident();
        assertEquals(resolver.getInfo(ident), NodeLoadExpression.INFO_LOAD);

        ident = NodeLoadExpression.INFO_LOAD_1.ident();
        assertEquals(resolver.getInfo(ident), NodeLoadExpression.INFO_LOAD_1);

    }

    @Test
    public void testChildImplementationLookup() throws Exception {
        ReferenceIdent ident = new ReferenceIdent(SystemReferences.NODES_IDENT, "load");
        SysObjectReference<Double> load = (SysObjectReference<Double>) resolver.getImplementation(ident);
        assertEquals(NodeLoadExpression.INFO_LOAD, load.info());

        ident = NodeLoadExpression.INFO_LOAD_1.ident();
        SysExpression<Double> l1 = (SysExpression<Double>) resolver.getImplementation(ident);
        assertEquals(NodeLoadExpression.INFO_LOAD_1, l1.info());

    }


    @Test
    public void testLoad() throws Exception {

        ReferenceIdent ident = new ReferenceIdent(SystemReferences.NODES_IDENT, "load");
        SysObjectReference<Double> load = (SysObjectReference<Double>) resolver.getImplementation(ident);

        Map<String, Double> v = load.value();
        assertNull(v.get("something"));
        assertEquals(new Double(1), v.get("1"));
        assertEquals(new Double(5), v.get("5"));
        assertEquals(new Double(15), v.get("15"));

        Input<Double> ci = load.getChildImplementation("1");
        assertEquals(new Double(1), ci.value());
        ci = load.getChildImplementation("5");
        assertEquals(new Double(5), ci.value());
        ci = load.getChildImplementation("15");
        assertEquals(new Double(15), ci.value());

    }

}
