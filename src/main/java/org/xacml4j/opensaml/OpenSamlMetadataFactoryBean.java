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
import java.util.Timer;

import org.joda.time.DateTime;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.ResourceBackedMetadataProvider;
import org.opensaml.util.resource.Resource;
import org.opensaml.util.resource.ResourceException;
import org.opensaml.xml.parse.BasicParserPool;
import org.springframework.beans.factory.config.AbstractFactoryBean;

import com.google.common.base.Preconditions;

public class OpenSamlMetadataFactoryBean extends AbstractFactoryBean<MetadataProvider> {

	private org.springframework.core.io.Resource metadata;

	public void setLocation(org.springframework.core.io.Resource location){
		this.metadata = location;
	}

	@Override
	public Class<?> getObjectType() {
		return MetadataProvider.class;
	}

	@Override
	protected MetadataProvider createInstance() throws Exception {
		Preconditions.checkState(metadata != null);
		ResourceBackedMetadataProvider mdp = new ResourceBackedMetadataProvider(
				new SpringResourceWrapper(metadata),
				new Timer(true),
				Integer.MAX_VALUE
				);
		BasicParserPool pool = new BasicParserPool();
		pool.setNamespaceAware(true);
		mdp.setParserPool(pool);
		mdp.initialize();
		return mdp;
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
