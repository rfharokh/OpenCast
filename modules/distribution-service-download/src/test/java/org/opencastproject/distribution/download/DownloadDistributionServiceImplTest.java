/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.distribution.download;

import org.opencastproject.distribution.api.DistributionService;
import org.opencastproject.job.api.Job;
import org.opencastproject.job.api.JobBarrier;
import org.opencastproject.mediapackage.MediaPackage;
import org.opencastproject.mediapackage.MediaPackageElement;
import org.opencastproject.mediapackage.MediaPackageElementParser;
import org.opencastproject.mediapackage.MediaPackageParser;
import org.opencastproject.security.api.DefaultOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.OrganizationDirectoryService;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.TrustedHttpClient;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserDirectoryService;
import org.opencastproject.security.util.StandAloneTrustedHttpClientImpl;
import org.opencastproject.serviceregistry.api.IncidentService;
import org.opencastproject.serviceregistry.api.ServiceRegistry;
import org.opencastproject.serviceregistry.api.ServiceRegistryInMemoryImpl;
import org.opencastproject.util.PathSupport;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.data.Either;
import org.opencastproject.util.data.Function;
import org.opencastproject.workspace.api.Workspace;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.StatusLine;
import org.apache.http.client.methods.HttpUriRequest;
import org.easymock.EasyMock;
import org.easymock.IAnswer;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;

import java.io.File;
import java.net.URI;
import java.util.Dictionary;
import java.util.Hashtable;

import javax.servlet.http.HttpServletResponse;

public class DownloadDistributionServiceImplTest {

  private DownloadDistributionServiceImpl service = null;
  private MediaPackage mp = null;
  private File distributionRoot = null;
  private ServiceRegistry serviceRegistry = null;
  private DefaultOrganization defaultOrganization;

  @Before
  public void setUp() throws Exception {
    final File mediaPackageRoot = new File(getClass().getResource("/mediapackage.xml").toURI()).getParentFile();
    mp = MediaPackageParser.getFromXml(IOUtils.toString(getClass().getResourceAsStream("/mediapackage.xml"), "UTF-8"));

    distributionRoot = new File(mediaPackageRoot, "static");
    service = new DownloadDistributionServiceImpl();

    StatusLine statusLine = EasyMock.createNiceMock(StatusLine.class);
    EasyMock.expect(statusLine.getStatusCode()).andReturn(HttpServletResponse.SC_OK).anyTimes();
    EasyMock.replay(statusLine);

    HttpResponse response = EasyMock.createNiceMock(HttpResponse.class);
    EasyMock.expect(response.getStatusLine()).andReturn(statusLine).anyTimes();
    EasyMock.replay(response);

    final TrustedHttpClient httpClient = EasyMock.createNiceMock(TrustedHttpClient.class);
    EasyMock.expect(httpClient.execute((HttpUriRequest) EasyMock.anyObject())).andReturn(response).anyTimes();
    EasyMock.expect(httpClient.run((HttpUriRequest) EasyMock.anyObject()))
            .andAnswer(new IAnswer<Function<Function<HttpResponse, Object>, Either<Exception, Object>>>() {
              @Override
              public Function<Function<HttpResponse, Object>, Either<Exception, Object>> answer() throws Throwable {
                HttpUriRequest req = (HttpUriRequest) EasyMock.getCurrentArguments()[0];
                return StandAloneTrustedHttpClientImpl.run(httpClient, req);
              }
            }).anyTimes();
    EasyMock.replay(httpClient);

    defaultOrganization = new DefaultOrganization();
    User anonymous = new JaxbUser("anonymous", "test", defaultOrganization,
            new JaxbRole(DefaultOrganization.DEFAULT_ORGANIZATION_ANONYMOUS, defaultOrganization));
    UserDirectoryService userDirectoryService = EasyMock.createMock(UserDirectoryService.class);
    EasyMock.expect(userDirectoryService.loadUser((String) EasyMock.anyObject())).andReturn(anonymous).anyTimes();
    EasyMock.replay(userDirectoryService);
    service.setUserDirectoryService(userDirectoryService);

    Organization organization = new DefaultOrganization();
    OrganizationDirectoryService organizationDirectoryService = EasyMock.createMock(OrganizationDirectoryService.class);
    EasyMock.expect(organizationDirectoryService.getOrganization((String) EasyMock.anyObject())).andReturn(organization)
            .anyTimes();
    EasyMock.replay(organizationDirectoryService);
    service.setOrganizationDirectoryService(organizationDirectoryService);

    SecurityService securityService = EasyMock.createNiceMock(SecurityService.class);
    EasyMock.expect(securityService.getUser()).andReturn(anonymous).anyTimes();
    EasyMock.expect(securityService.getOrganization()).andReturn(organization).anyTimes();
    EasyMock.replay(securityService);
    service.setSecurityService(securityService);

    serviceRegistry = new ServiceRegistryInMemoryImpl(service, securityService, userDirectoryService,
            organizationDirectoryService, EasyMock.createNiceMock(IncidentService.class));
    service.setServiceRegistry(serviceRegistry);
    service.setTrustedHttpClient(httpClient);

    final Workspace workspace = EasyMock.createNiceMock(Workspace.class);
    service.setWorkspace(workspace);

    EasyMock.expect(workspace.get((URI) EasyMock.anyObject())).andAnswer(new IAnswer<File>() {
      @Override
      public File answer() throws Throwable {
        final URI uri = (URI) EasyMock.getCurrentArguments()[0];
        final String[] pathElems = uri.getPath().split("/");
        final String file = pathElems[pathElems.length - 1];
        return new File(mediaPackageRoot, file);
      }
    }).anyTimes();
    EasyMock.replay(workspace);

    BundleContext bc = EasyMock.createNiceMock(BundleContext.class);
    EasyMock.expect(bc.getProperty("org.opencastproject.download.directory")).andReturn(distributionRoot.toString()).anyTimes();
    EasyMock.expect(bc.getProperty("org.opencastproject.download.url")).andReturn(UrlSupport.DEFAULT_BASE_URL).anyTimes();
    ComponentContext cc = EasyMock.createNiceMock(ComponentContext.class);
    Dictionary<String, Object> p = new Hashtable<String, Object>();
    p.put(DistributionService.CONFIG_KEY_STORE_TYPE, "download");
    EasyMock.expect(cc.getProperties()).andReturn(p).anyTimes();
    EasyMock.expect(cc.getBundleContext()).andReturn(bc).anyTimes();
    EasyMock.replay(bc, cc);
    service.activate(cc);
  }

  @After
  public void tearDown() throws Exception {
    FileUtils.deleteDirectory(distributionRoot);
    ((ServiceRegistryInMemoryImpl) serviceRegistry).dispose();
  }

  @Test
  public void testPartialDistribution() throws Exception {
    // Distribute only some of the elements in the mediapackage
    Job job1 = service.distribute("engage-player", mp, "track-1");
    Job job2 = service.distribute("engage-player", mp, "catalog-1");
    Job job3 = service.distribute("oai-pmh", mp, "catalog-1");
    JobBarrier jobBarrier = new JobBarrier(null, serviceRegistry, 500, job1, job2, job3);
    jobBarrier.waitForJobs();

    File mpDir = new File(distributionRoot,
            PathSupport.path(defaultOrganization.getId(), "engage-player", mp.getIdentifier().toString()));
    Assert.assertTrue(mpDir.exists());
    File mediaDir = new File(mpDir, "track-1");
    File metadataDir = new File(mpDir, "catalog-1");
    File attachmentsDir = new File(mpDir, "notes");
    Assert.assertTrue(mediaDir.exists());
    Assert.assertTrue(metadataDir.exists());
    Assert.assertFalse(attachmentsDir.exists());
    Assert.assertTrue(new File(mediaDir, "media.mov").exists()); // the filenames are changed to reflect the element ID
    Assert.assertTrue(new File(metadataDir, "dublincore.xml").exists());
    Assert.assertFalse(new File(metadataDir, "mpeg7.xml").exists());
    Assert.assertFalse(new File(attachmentsDir, "attachment.txt").exists());
  }

  @Test
  public void testRetractByOriginal() throws Exception {
    // Distribute the mediapackage and all of its elements
    Job job1 = service.distribute("engage-player", mp, "track-1");
    Job job2 = service.distribute("engage-player", mp, "catalog-1");
    Job job3 = service.distribute("engage-player", mp, "catalog-2");
    Job job4 = service.distribute("engage-player", mp, "notes");
    Job job5 = service.distribute("oai-pmh", mp, "track-1");
    JobBarrier jobBarrier = new JobBarrier(null, serviceRegistry, 500, job1, job2, job3, job4, job5);
    jobBarrier.waitForJobs();

    // Add the new elements to the mediapackage
    mp.add(MediaPackageElementParser.getFromXml(job1.getPayload()));
    mp.add(MediaPackageElementParser.getFromXml(job2.getPayload()));
    mp.add(MediaPackageElementParser.getFromXml(job3.getPayload()));
    mp.add(MediaPackageElementParser.getFromXml(job4.getPayload()));
    mp.add(MediaPackageElementParser.getFromXml(job5.getPayload()));

    File mpDir = new File(distributionRoot,
            PathSupport.path(defaultOrganization.getId(), "engage-player", mp.getIdentifier().toString()));
    File mediaDir = new File(mpDir, "track-1");
    File metadata1Dir = new File(mpDir, "catalog-1");
    File metadata2Dir = new File(mpDir, "catalog-2");
    File attachmentsDir = new File(mpDir, "notes");
    Assert.assertTrue(mediaDir.exists());
    Assert.assertTrue(metadata1Dir.exists());
    Assert.assertTrue(metadata2Dir.exists());
    Assert.assertTrue(attachmentsDir.exists());
    Assert.assertTrue(new File(mediaDir, "media.mov").exists()); // the filenames are changed to reflect the element ID
    Assert.assertTrue(new File(metadata1Dir, "dublincore.xml").exists());
    Assert.assertTrue(new File(metadata2Dir, "mpeg7.xml").exists());
    Assert.assertTrue(new File(attachmentsDir, "attachment.txt").exists());

    // Now retract the mediapackage and ensure that the distributed files have been removed
    Job job6 = service.retract("engage-player", mp, "track-1");
    Job job7 = service.retract("engage-player", mp, "catalog-1");
    Job job8 = service.retract("engage-player", mp, "catalog-2");
    Job job9 = service.retract("engage-player", mp, "notes");
    jobBarrier = new JobBarrier(null, serviceRegistry, 500, job6, job7, job8, job9);
    jobBarrier.waitForJobs();

    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("track-1")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("catalog-1")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("catalog-2")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("notes")).isFile());
    Assert.assertTrue(service.getDistributionFile("oai-pmh", mp, mp.getElementById("track-1")).isFile());
  }

  @Test
  public void testRetractByDistributed() throws Exception {
    int elementCount = mp.getElements().length;

    // Distribute the mediapackage and all of its elements
    Job job1 = service.distribute("engage-player", mp, "track-1");
    Job job2 = service.distribute("engage-player", mp, "catalog-1");
    Job job3 = service.distribute("engage-player", mp, "catalog-2");
    Job job4 = service.distribute("engage-player", mp, "notes");
    Job job5 = service.distribute("oai-pmh", mp, "notes");
    JobBarrier jobBarrier = new JobBarrier(null, serviceRegistry, 500, job1, job2, job3, job4, job5);
    jobBarrier.waitForJobs();

    // Add the new elements to the mediapackage
    MediaPackageElement job1Element = MediaPackageElementParser.getFromXml(job1.getPayload());
    mp.add(job1Element);
    MediaPackageElement job2Element = MediaPackageElementParser.getFromXml(job2.getPayload());
    mp.add(job2Element);
    MediaPackageElement job3Element = MediaPackageElementParser.getFromXml(job3.getPayload());
    mp.add(job3Element);
    MediaPackageElement job4Element = MediaPackageElementParser.getFromXml(job4.getPayload());
    mp.add(job4Element);
    MediaPackageElement job5Element = MediaPackageElementParser.getFromXml(job5.getPayload());
    mp.add(job5Element);

    File mpDir = new File(distributionRoot,
            PathSupport.path(defaultOrganization.getId(), "engage-player", mp.getIdentifier().toString()));
    File mediaDir = new File(mpDir, "track-1");
    File metadata1Dir = new File(mpDir, "catalog-1");
    File metadata2Dir = new File(mpDir, "catalog-2");
    File attachmentsDir = new File(mpDir, "notes");
    Assert.assertTrue(mediaDir.exists());
    Assert.assertTrue(metadata1Dir.exists());
    Assert.assertTrue(metadata2Dir.exists());
    Assert.assertTrue(attachmentsDir.exists());
    Assert.assertTrue(new File(mediaDir, "media.mov").exists()); // the filenames are changed to reflect the element ID
    Assert.assertTrue(new File(metadata1Dir, "dublincore.xml").exists());
    Assert.assertTrue(new File(metadata2Dir, "mpeg7.xml").exists());
    Assert.assertTrue(new File(attachmentsDir, "attachment.txt").exists());

    // Now retract the mediapackage and ensure that the distributed files have been removed
    Job job6 = service.retract("engage-player", mp, job1Element.getIdentifier());
    Job job7 = service.retract("engage-player", mp, job2Element.getIdentifier());
    Job job8 = service.retract("engage-player", mp, job3Element.getIdentifier());
    Job job9 = service.retract("engage-player", mp, job4Element.getIdentifier());
    jobBarrier = new JobBarrier(null, serviceRegistry, 500, job6, job7, job8, job9);
    jobBarrier.waitForJobs();

    // Remove the distributed elements from the mediapackage
    mp.remove(MediaPackageElementParser.getFromXml(job6.getPayload()));
    mp.remove(MediaPackageElementParser.getFromXml(job7.getPayload()));
    mp.remove(MediaPackageElementParser.getFromXml(job8.getPayload()));
    mp.remove(MediaPackageElementParser.getFromXml(job9.getPayload()));

    // +1 since the oai-pmh distribution has not been retracted
    Assert.assertEquals(elementCount + 1, mp.getElements().length);
    Assert.assertNotNull(mp.getElementById("track-1"));
    Assert.assertNotNull(mp.getElementById("catalog-1"));
    Assert.assertNotNull(mp.getElementById("catalog-2"));
    Assert.assertNotNull(mp.getElementById("notes"));

    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("track-1")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("catalog-1")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("catalog-2")).isFile());
    Assert.assertFalse(service.getDistributionFile("engage-player", mp, mp.getElementById("notes")).isFile());
    Assert.assertTrue(service.getDistributionFile("oai-pmh", mp, mp.getElementById("notes")).isFile());
  }

}
