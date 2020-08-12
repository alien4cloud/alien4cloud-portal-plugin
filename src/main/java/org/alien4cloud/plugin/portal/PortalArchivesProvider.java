package org.alien4cloud.plugin.portal;

import alien4cloud.plugin.archives.AbstractArchiveProviderPlugin;
import org.springframework.stereotype.Component;

@Component("portalplugin-archives-provider")
public class PortalArchivesProvider extends AbstractArchiveProviderPlugin {
    @Override
    protected String[] getArchivesPaths() {
        return new String[] { "csar" };
    }
}
