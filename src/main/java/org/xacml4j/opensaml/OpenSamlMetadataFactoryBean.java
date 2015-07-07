package org.xacml4j.opensaml;

/*
 * #%L
 * XACML/OpenSAML Integration
 * %%
 * Copyright (C) 2009 - 2014 Xacml4J.org
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Lesser Public License for more details.
 * 
 * You should have received a copy of the GNU General Lesser Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/lgpl-3.0.html>.
 * #L%
 */

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Timer;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPathExpressionException;

import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.provider.ChainingMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.beans.factory.config.AbstractFactoryBean;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.core.io.support.ResourcePatternResolver;
import org.xml.sax.SAXException;

import com.google.common.base.Preconditions;
import com.google.common.collect.Lists;

public class OpenSamlMetadataFactoryBean extends AbstractFactoryBean<MetadataProvider> {

    private final ResourcePatternResolver resourcePatternResolver = new PathMatchingResourcePatternResolver();
	private Collection<org.springframework.core.io.Resource> metadata;
	private boolean bootStrapped = false;
	private Timer timer = new Timer(true);

	public void setLocation(org.springframework.core.io.Resource resource) throws IOException{
		this.metadata = Lists.newLinkedList();
		if (resource != null) {
			metadata.add(resource);
		}
	}

	public void setLocations(List<String> locations) throws XPathExpressionException, TransformerException, ParserConfigurationException, SAXException, IOException{
		this.metadata = Lists.newLinkedList();
        for (String resourceLocation : locations) {
        	if (resourceLocation != null) {
        		Collections.addAll(metadata, resourcePatternResolver.getResources(resourceLocation));
        	}
        }
	}

	@Override
	public Class<?> getObjectType() {
		return MetadataProvider.class;
	}

	@Override
	protected MetadataProvider createInstance() throws MetadataProviderException, ConfigurationException {
		if (!bootStrapped) {
			DefaultBootstrap.bootstrap();
			bootStrapped=true;
		}
		Preconditions.checkState(metadata != null);
		ResourceBackedMetadataProvider mdp = null;
		ChainingMetadataProvider cmp = new ChainingMetadataProvider();
		BasicParserPool pool = new BasicParserPool();
		pool.setNamespaceAware(true);

		for (org.springframework.core.io.Resource provider : metadata) {
			mdp = new ResourceBackedMetadataProvider(
					new SpringResourceWrapper(provider),
					timer,
					Integer.MAX_VALUE
					);
			mdp.setParserPool(pool);
			mdp.initialize();
			cmp.addMetadataProvider(mdp);
		}
		return cmp;
	}

	public static class SpringResourceWrapper implements Resource {

		private final org.springframework.core.io.Resource source;

		public SpringResourceWrapper(org.springframework.core.io.Resource source) {
			this.source = source;
		}

		@Override public boolean exists() throws ResourceException {
			return source.exists();
		}

		@Override public InputStream getInputStream() throws ResourceException {
			try {
				return source.getInputStream();
			} catch (IOException e) {
				throw new ResourceException(e);
			}
		}

		@Override public DateTime getLastModifiedTime() throws ResourceException {
			try {
				return new DateTime(source.lastModified());
			} catch (IOException e) {
				throw new ResourceException(e);
			}
		}

		@Override public String getLocation() {
			return source.getDescription();
		}
	}
}
